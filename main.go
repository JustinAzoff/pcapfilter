package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/JustinAzoff/pcapfilter/pcap_indexer"
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

func Filter(r *os.File, ir io.Reader, w io.Writer, filters []filter) (uint64, error) {
	packets := uint64(0)

	pr, err := pcap_indexer.NewReader(r, ir)
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
	fmt.Fprintf(os.Stderr, "Usage: %s in.pcap out.pcap query\nWhere query is 'body foo' or 'ip 1.2.3.4/32\n", os.Args[0])
	os.Exit(1)
}
func main() {
	if len(os.Args) < 5 {
		usage()
	}
	f := os.Args[1]
	of := os.Args[2]
	fs, err := parseQuery(os.Args[3:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid query: %v\n", err)
		usage()
	}
	if len(fs) == 0 {
		fmt.Fprintf(os.Stderr, "Missing query\n")
		usage()
	}

	infile, err := os.Open(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening input: %v\n", err)
		os.Exit(1)
	}
	outfile, err := os.Create(of)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening output: %v\n", err)
		os.Exit(1)
	}

	indexFilename := strings.Replace(f, ".pcap", ".idx", 1)
	if _, err := os.Stat(indexFilename); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Index %s does not exist, creating\n", indexFilename)
		indexw, err := os.Create(indexFilename)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening index for writing: %v\n", err)
			os.Exit(1)
		}
		pcap_indexer.IndexPCAP(infile, indexw, 128*1024)
		infile.Seek(0, os.SEEK_SET)
	}

	indexr, err := os.Open(indexFilename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening index: %v\n", err)
		os.Exit(1)
	}

	pkts, err := Filter(infile, indexr, outfile, fs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Wrote %d packets\n", pkts)
}
