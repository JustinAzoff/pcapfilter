package main

import (
	"log"
	"os"

	"github.com/JustinAzoff/pcapfilter/pcap_indexer"
)

func main() {
	f := os.Args[1]
	idx := os.Args[2]

	r, err := os.Open(f)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()

	w, err := os.Create(idx)
	if err != nil {
		log.Fatal(err)
	}
	defer w.Close()

	err = pcap_indexer.IndexPCAP(r, w, 128*1024)
	if err != nil {
		log.Fatal(err)
	}
}
