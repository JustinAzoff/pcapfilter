package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type filter []byte

func IPNetToFilterableBytes(n *net.IPNet) []byte {
	filter := make([]byte, 0, len(n.IP))
	for i := 0; i < len(n.IP); i++ {
		if n.Mask[i] == 0xff {
			filter = append(filter, n.IP[i])
		}
	}
	return filter
}

func IPToFilter(ip string) (filter, error) {
	var ipnet *net.IPNet
	var netBytes []byte
	_, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return filter{}, err
	}
	netBytes = IPNetToFilterableBytes(ipnet)
	return filter(netBytes), nil
}

func Filter(r *os.File, w io.Writer, filters []filter) (uint64, error) {
	packets := uint64(0)

	pr, err := NewReader(r)
	if err != nil {
		return 0, err
	}

	pw := pcapgo.NewWriter(w)
	pw.WriteFileHeader(65536, layers.LinkTypeEthernet)

	for {
		packetData, captureInfo, err := pr.ReadPacketData(filters[0])
		if err == io.EOF {
			break
		}
		if err != nil {
			return packets, err
		}

		err = pw.WritePacket(captureInfo, packetData)
		if err != nil {
			return packets, err
		}
		packets++
	}

	return packets, nil
}

func parseQuery(query []string) ([]filter, error) {
	var filters []filter
	for i, s := range query {
		if i > 0 && query[i-1] == "body" {
			filters = append(filters, filter(s))
		}
		if i > 0 && query[i-1] == "ip" {
			ip, err := IPToFilter(s)
			if err != nil {
				return filters, err
			}
			filters = append(filters, ip)
		}
	}
	return filters, nil
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
