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
	offsets []uint32
	offset  int
	r       io.Reader
	err     error
}

func (r *IndexReader) Fill() {
	for {
		delta, err := r.readNextOffsetDelta()
		if err == io.EOF {
			break
		}
		r.offsets = append(r.offsets, delta)
		if err != nil {
			r.err = err
			break
		}
	}
}

func (r *IndexReader) readNextOffsetDelta() (uint32, error) {
	var delta uint32
	err := binary.Read(r.r, binary.BigEndian, &delta)
	return delta, err
}

func (r *IndexReader) ReadNextOffsetDelta() (uint32, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.offset >= len(r.offsets) {
		return 0, io.EOF
	}
	delta := r.offsets[r.offset]
	r.offset++
	return delta, nil
}

func NewIndexReader(r io.Reader) *IndexReader {
	indexer := IndexReader{
		r: r,
	}
	indexer.Fill()
	return &indexer
}
