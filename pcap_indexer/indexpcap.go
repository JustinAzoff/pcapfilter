package pcap_indexer

import (
	"io"
	"log"

	"github.com/google/gopacket/pcapgo"
)

func IndexPCAP(r io.Reader, w io.Writer, maxOffset int) error {
	pr, err := pcapgo.NewReader(r)
	if err != nil {
		return err
	}

	ow := NewIndexWriter(w)

	pos := 0
	lastPos := pos
	nextPos := 0
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
		nextPos = pos + 16 + captureInfo.CaptureLength
		//log.Printf("packet: %d, pos: %d, len: %d", pkt, pos, captureInfo.CaptureLength)
		if nextPos-lastPos > maxOffset {
			ow.WriteOffset(pos)
			log.Printf("Wrote offset: %d", pos)
			lastPos = pos
		}
		pos = nextPos
	}
	return nil

}
