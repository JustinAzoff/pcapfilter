package main

import (
	"io"
	"log"
	"os"

	"github.com/JustinAzoff/pcapfilter/pcap_indexer"
	"github.com/google/gopacket/pcapgo"
)

func IndexPCAP(r io.Reader, w io.Writer, minOffset int) error {
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return err
	}

	ow := pcap_indexer.NewIndexWriter(w)

	lastPos := 0
	pos := 24
	pkt := 1
	for {
		_, captureInfo, err := pr.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		pkt++
		pos += 16 + captureInfo.CaptureLength
		//log.Printf("packet: %d, pos: %d, len: %d", pkt, pos, captureInfo.CaptureLength)
		if pos-lastPos > minOffset {
			ow.WriteOffset(pos)
			//log.Printf("Wrote offset: %d", pos)
			lastPos = pos
		}
	}
	return nil

}

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

	err = IndexPCAP(r, w, 128*1024)
	if err != nil {
		log.Fatal(err)
	}
}
