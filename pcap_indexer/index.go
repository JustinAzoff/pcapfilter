package pcap_indexer

import (
	"encoding/binary"
	"io"
)

type IndexWriter struct {
	lastOffset int
	w          io.Writer
}

func (w *IndexWriter) WriteOffset(n int) error {
	diff := uint32(n - w.lastOffset)
	w.lastOffset = n
	return binary.Write(w.w, binary.BigEndian, diff)
}

func NewIndexWriter(w io.Writer) *IndexWriter {
	return &IndexWriter{w: w}
}

type IndexReader struct {
	lastOffset int
	r          io.Reader
}

func (r *IndexReader) ReadNextOffsetDelta() (uint32, error) {
	var delta uint32
	err := binary.Read(r.r, binary.BigEndian, &delta)
	return delta, err
}

func NewIndexReader(r io.Reader) *IndexReader {
	return &IndexReader{r: r}
}
