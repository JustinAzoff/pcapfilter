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
	for i, arg := range query {
		if i%2 == 0 {
			continue
		}
		op := query[i-1]
		if op == "body" {
			filters = append(filters, filter(arg))
		} else if op == "ip" {
			ip, err := IPToFilter(arg)
			if err != nil {
				return filters, err
			}
			filters = append(filters, ip)
		} else {
			return filters, fmt.Errorf("Invalid filter %s", op)
		}
	}
	return filters, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s query < in.pcap > out.pcap\nWhere query is 'body foo' or 'ip 1.2.3.4/32\n", os.Args[0])
	os.Exit(1)
}
func main() {
	if len(os.Args) < 3 {
		usage()
	}
	fs, err := parseQuery(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid query: %v\n", err)
		usage()
	}
	if len(fs) == 0 {
		fmt.Fprintf(os.Stderr, "Missing query\n")
		usage()
	}

	pkts, err := Filter(os.Stdin, os.Stdout, fs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d packets\n", pkts)
}
