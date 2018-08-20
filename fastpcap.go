package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const headerSize = 16
const blockSize = 128 * 1024

type Reader struct {
	r              io.Reader
	byteOrder      binary.ByteOrder
	nanoSecsFactor uint32
	versionMajor   uint16
	versionMinor   uint16
	// timezone
	// sigfigs
	snaplen  uint32
	linkType layers.LinkType
	// reusable buffer
	buf [16]byte

	block      [blockSize]byte
	blockSlice []byte

	bnum int
	pnum int
}

const magicMicroseconds = 0xA1B2C3D4
const versionMajor = 2
const versionMinor = 4
const magicNanoseconds = 0xA1B23C4D
const magicMicrosecondsBigendian = 0xD4C3B2A1
const magicNanosecondsBigendian = 0x4D3CB2A1

const magicGzip1 = 0x1f
const magicGzip2 = 0x8b

func NewReader(r io.Reader) (*Reader, error) {
	ret := Reader{r: r}
	if err := ret.readHeader(); err != nil {
		return nil, err
	}
	ret.initBuffers()
	return &ret, nil
}

func (r *Reader) initBuffers() {
	n, _ := io.ReadFull(r.r, r.block[:])
	r.blockSlice = r.block[:n]
}

func (r *Reader) readHeader() error {
	br := bufio.NewReader(r.r)
	gzipMagic, err := br.Peek(2)
	if err != nil {
		return err
	}

	if gzipMagic[0] == magicGzip1 && gzipMagic[1] == magicGzip2 {
		if r.r, err = gzip.NewReader(br); err != nil {
			return err
		}
	} else {
		r.r = br
	}

	buf := make([]byte, 24)
	if n, err := io.ReadFull(r.r, buf); err != nil {
		return err
	} else if n < 24 {
		return errors.New("Not enough data for read")
	}
	if magic := binary.LittleEndian.Uint32(buf[0:4]); magic == magicNanoseconds {
		r.byteOrder = binary.LittleEndian
		r.nanoSecsFactor = 1
	} else if magic == magicNanosecondsBigendian {
		r.byteOrder = binary.BigEndian
		r.nanoSecsFactor = 1
	} else if magic == magicMicroseconds {
		r.byteOrder = binary.LittleEndian
		r.nanoSecsFactor = 1000
	} else if magic == magicMicrosecondsBigendian {
		r.byteOrder = binary.BigEndian
		r.nanoSecsFactor = 1000
	} else {
		return fmt.Errorf("Unknown magic %x", magic)
	}
	if r.versionMajor = r.byteOrder.Uint16(buf[4:6]); r.versionMajor != versionMajor {
		return fmt.Errorf("Unknown major version %d", r.versionMajor)
	}
	if r.versionMinor = r.byteOrder.Uint16(buf[6:8]); r.versionMinor != versionMinor {
		return fmt.Errorf("Unknown minor version %d", r.versionMinor)
	}
	// ignore timezone 8:12 and sigfigs 12:16
	r.snaplen = r.byteOrder.Uint32(buf[16:20])
	r.linkType = layers.LinkType(r.byteOrder.Uint32(buf[20:24]))
	return nil
}

func (r *Reader) Fill() int {
	//log.Printf("Filling...")
	curLen := len(r.blockSlice)
	//log.Printf("Need %d, have %d", packetLength, curLen)
	//log.Printf("Need to Read %d more bytes", blockSize-curLen)
	//log.Printf("Moving %d bytes to the beginning", curLen)
	copy(r.block[:], r.blockSlice[:])
	n, _ := io.ReadFull(r.r, r.block[curLen:])
	//log.Printf("Read %d bytes", n)
	r.blockSlice = r.block[:curLen+n]
	r.bnum++
	return n
}

func (r *Reader) SkipPackets() bool {
	var err error
	var packetLength int
	for {
		if headerSize > len(r.blockSlice) {
			n := r.Fill()
			return n > 0
		}
		packetLength, err = r.getPacketLength()
		if err != nil {
			log.Fatal(err)
			return false
		}
		if packetLength == 0 {
			return false
		}
		if 16+packetLength > len(r.blockSlice) {
			n := r.Fill()
			return n > 0
		}
		r.blockSlice = r.blockSlice[16:]           // Skip Header
		r.blockSlice = r.blockSlice[packetLength:] // Skip Packet
		r.pnum++
	}
}

func (r *Reader) FindPacket(query []byte) (data []byte, ci gopacket.CaptureInfo, more bool, err error) {
	var packetLength int
	for {
		if headerSize > len(r.blockSlice) {
			n := r.Fill()
			more = n > 0
			return
		}
		packetLength, err = r.getPacketLength()
		if packetLength == 0 {
			return
		}
		if err != nil {
			return
		}
		if 16+packetLength > len(r.blockSlice) {
			n := r.Fill()
			more = n > 0
			return
		}
		if bytes.Contains(r.blockSlice[16:packetLength+16], query) {
			//log.Printf("Pattern WAS found in packet %d\n", r.pnum)
			ci, err := r.readPacketHeader()
			if err != nil {
				return []byte{}, ci, false, err
			}
			data := r.blockSlice[:packetLength]
			r.blockSlice = r.blockSlice[packetLength:] // Skip Packet
			return data, ci, false, nil
		}
		r.blockSlice = r.blockSlice[16:]           // Skip Header
		r.blockSlice = r.blockSlice[packetLength:] // Skip Packet
		r.pnum++
	}
}

// ReadPacketData reads next packet from file.
func (r *Reader) ReadPacketData(query []byte) (data []byte, ci gopacket.CaptureInfo, err error) {
	for {
		//log.Printf("Start!\n")
		if bytes.Contains(r.blockSlice, query) {
			// Decode and return this block
			//log.Printf("Pattern WAS found in block %d\n", r.bnum)
			data, ci, more, err := r.FindPacket(query)
			if more {
				continue
			}
			return data, ci, err
		} else {
			//log.Printf("Pattern NOT found in block %d\n", r.bnum)
			//skip this entire block
			if !r.SkipPackets() {
				break
			}
		}
	}
	err = io.EOF
	return
}
func (r *Reader) getPacketLength() (length int, err error) {
	if len(r.blockSlice) < 16 {
		return 0, fmt.Errorf("getPacketLength: blockSlice too small?")
	}
	length = int(r.byteOrder.Uint32(r.blockSlice[12:16]))
	return
}

func (r *Reader) readPacketHeader() (ci gopacket.CaptureInfo, err error) {
	if len(r.blockSlice) < 16 {
		err = fmt.Errorf("blockSlice too small?")
		return
	}
	ci.Timestamp = time.Unix(int64(r.byteOrder.Uint32(r.blockSlice[0:4])), int64(r.byteOrder.Uint32(r.blockSlice[4:8])*r.nanoSecsFactor)).UTC()
	ci.CaptureLength = int(r.byteOrder.Uint32(r.blockSlice[8:12]))
	ci.Length = int(r.byteOrder.Uint32(r.blockSlice[12:16]))
	r.blockSlice = r.blockSlice[16:]
	return
}

// LinkType returns network, as a layers.LinkType.
func (r *Reader) LinkType() layers.LinkType {
	return r.linkType
}

// Snaplen returns the snapshot length of the capture file.
func (r *Reader) Snaplen() uint32 {
	return r.snaplen
}

// SetSnaplen sets the snapshot length of the capture file.
//
// This is useful when a pcap file contains packets bigger than then snaplen.
// Pcapgo will error when reading packets bigger than snaplen, then it dumps those
// packets and reads the next 16 bytes, which are part of the "faulty" packet's payload, but pcapgo
// thinks it's the next header, which is probably also faulty because it's not really a packet header.
// This can lead to a lot of faulty reads.
//
// The SetSnaplen function can be used to set a bigger snaplen to prevent those read errors.
//
// This snaplen situation can happen when a pcap writer doesn't truncate packets to the snaplen size while writing packets to file.
// E.g. In Python, dpkt.pcap.Writer sets snaplen by default to 1500 (https://dpkt.readthedocs.io/en/latest/api/api_auto.html#dpkt.pcap.Writer)
// but doesn't enforce this when writing packets (https://dpkt.readthedocs.io/en/latest/_modules/dpkt/pcap.html#Writer.writepkt).
// When reading, tools like tcpdump, tcpslice, mergecap and wireshark ignore the snaplen and use
// their own defined snaplen.
// E.g. When reading packets, tcpdump defines MAXIMUM_SNAPLEN (https://github.com/the-tcpdump-group/tcpdump/blob/6e80fcdbe9c41366df3fa244ffe4ac8cce2ab597/netdissect.h#L290)
// and uses it (https://github.com/the-tcpdump-group/tcpdump/blob/66384fa15b04b47ad08c063d4728df3b9c1c0677/print.c#L343-L358).
//
// For further reading:
//  - https://github.com/the-tcpdump-group/tcpdump/issues/389
//  - https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8808
//  - https://www.wireshark.org/lists/wireshark-dev/201307/msg00061.html
//  - https://github.com/wireshark/wireshark/blob/bfd51199e707c1d5c28732be34b44a9ee8a91cd8/wiretap/pcap-common.c#L723-L742
//    - https://github.com/wireshark/wireshark/blob/f07fb6cdfc0904905627707b88450054e921f092/wiretap/libpcap.c#L592-L598
//    - https://github.com/wireshark/wireshark/blob/f07fb6cdfc0904905627707b88450054e921f092/wiretap/libpcap.c#L714-L727
//  - https://github.com/the-tcpdump-group/tcpdump/commit/d033c1bc381c76d13e4aface97a4f4ec8c3beca2
//  - https://github.com/the-tcpdump-group/tcpdump/blob/88e87cb2cb74c5f939792171379acd9e0efd8b9a/netdissect.h#L263-L290
func (r *Reader) SetSnaplen(newSnaplen uint32) {
	r.snaplen = newSnaplen
}

// Reader formater
func (r *Reader) String() string {
	return fmt.Sprintf("PcapFile  maj: %x min: %x snaplen: %d linktype: %s", r.versionMajor, r.versionMinor, r.snaplen, r.linkType)
}

/*
func main() {
	fn := os.Args[1]
	outfn := os.Args[2]
	query := []byte(os.Args[3])

	file, err := os.Open(fn)
	if err != nil {
		log.Fatal(err)
	}
	reader, err := NewReader(file)
	if err != nil {
		log.Fatal(err)
	}

	outf, err := os.Create(outfn)
	if err != nil {
		log.Fatal(err)
	}

	pw := pcapgo.NewWriter(outf)
	pw.WriteFileHeader(65536, layers.LinkTypeEthernet)

	for {
		data, ci, err := reader.ReadPacketData(query)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		err = pw.WritePacket(ci, data)
	}
}
*/
