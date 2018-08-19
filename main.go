package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type FilterSpec struct {
	body []byte
	ip   string
}

func IPNetToFilterableBytes(n *net.IPNet) []byte {
	filter := make([]byte, 0, len(n.IP))
	for i := 0; i < len(n.IP); i++ {
		if n.Mask[i] == 0xff {
			filter = append(filter, n.IP[i])
		}
	}
	return filter
}

func Filter(r io.Reader, w io.Writer, fs FilterSpec) (uint64, error) {
	packets := uint64(0)

	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return 0, err
	}
	pw := pcapgo.NewWriter(w)
	pw.WriteFileHeader(65536, layers.LinkTypeEthernet)

	var ipnet *net.IPNet
	var netBytes []byte
	if fs.ip != "" {
		_, ipnet, err = net.ParseCIDR(fs.ip)
		if err != nil {
			return 0, err
		}
		netBytes = IPNetToFilterableBytes(ipnet)
	}

	for {
		packetData, captureInfo, err := pr.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return packets, err
		}

		if len(fs.body) > 0 && !bytes.Contains(packetData, fs.body) {
			continue
		}
		if len(netBytes) > 0 && !bytes.Contains(packetData, netBytes) {
			continue
		}

		err = pw.WritePacket(captureInfo, packetData)
		if err != nil {
			return packets, err
		}
		packets++
	}

	return packets, nil
}

func parseQuery(query []string) (FilterSpec, error) {
	fs := FilterSpec{}
	for i, s := range query {
		if i > 0 && query[i-1] == "body" {
			fs.body = []byte(s)
		}
		if i > 0 && query[i-1] == "ip" {
			fs.ip = s
		}
	}
	return fs, nil
}

func main() {
	fs, err := parseQuery(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid query %v", os.Args[1:])
		os.Exit(1)
	}

	pkts, err := Filter(os.Stdin, os.Stdout, fs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d packets\n", pkts)
}
