// Package bplist implements a parser and writer for binary property list files.
package bplist

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math"
	"time"
)

// A Handler provides callbacks to handle objects from a property list.  If a
// handler method reports an error, that error is propagated to the caller.
type Handler interface {
	// Called for the version string, e.g., "00".
	Version(string) error
	// Called for a null value.
	Null() error
	// Called for a Boolean value.
	Bool(bool) error
	// Called for an integer value.
	Int(int64) error
	// Called for a floating-point value.
	Float(float64) error
	// Called for a timestamp.
	Time(time.Time) error
	// Called for a byte array.
	Bytes([]byte) error
	// Called for a string.
	String(string) error
	// Called for a UID.
	UID([]byte) error

	// Called to signal the beginning of an array of n elements.
	BeginArray(n int) error
	// Called to signal the end of an array.
	EndArray() error

	// Called to signal the beginning of a dictionary of n pairs.
	BeginDict(n int) error
	// Called to signal the end of a dictionary.
	EndDict() error

	// Called to signal the beginning of a set of n elements.
	BeginSet(n int) error
	// Called to signal the end of a set.
	EndSet() error
}

func Parse(data []byte, h Handler) error {
	const magic = "bplist"
	const trailerBytes = 32
	if !bytes.HasPrefix(data, []byte(magic)) {
		return errors.New("invalid magic number")
	} else if len(data) < len(magic)+2+trailerBytes {
		return errors.New("invalid file structure")
	}

	// Call the Version handler eagerly, to give the caller a chance to bail out
	// for an incompatible version before we do more work.
	pos := len(magic)
	if err := h.Version(string(data[pos : pos+2])); err != nil {
		return err
	}

	t := parseTrailer(data[len(data)-32:])
	if t.tableEnd() > len(data)-32 {
		log.Printf("MJF :: len(data)=%d tableEnd=%d", len(data), t.tableEnd())
		return errors.New("invalid offsets table")
	}
	offsets := make([]int, t.NumObjects)
	for i := 0; i < len(offsets); i++ {
		base := t.OffsetTable + t.OffsetBytes*i
		offsets[i] = int(parseInt(data[base : base+t.OffsetBytes]))
	}

	var parseObj func(int) error
	parseObj = func(id int) error {
		off := offsets[id]
		tag := data[off]

		switch tag >> 4 {
		case 0: // null, bool, fill
			switch tag & 0xf {
			case 0:
				return h.Null()
			case 8:
				return h.Bool(false)
			case 9:
				return h.Bool(true)
			}

		case 1: // int
			size := 1 << (tag & 0xf)
			return h.Int(parseInt(data[off+1 : off+1+size]))

		case 2: // real
			size := 1 << (tag & 0xf)
			return h.Float(parseFloat(data[off+1 : off+1+size]))

		case 3: // date
			if tag&0xf == 3 {
				const macEpoch = 978307200 // 01-Jan-2001
				sec := parseFloat(data[off+1 : off+9])
				return h.Time(time.Unix(int64(sec)+macEpoch, 0).In(time.UTC))
			}

		case 4: // data
			size, shift := sizeAndShift(tag, data[off+1:])
			start := off + 1 + shift
			end := start + size
			return h.Bytes(data[start:end])

		case 5: // ASCII string
			size, shift := sizeAndShift(tag, data[off+1:])
			start := off + 1 + shift
			end := start + size
			return h.String(string(data[start:end]))

		case 6: // Unicode string
			// TODO

		case 8: // UID
			// TODO

		case 10: // array
			size, shift := sizeAndShift(tag, data[off+1:])
			if err := h.BeginArray(size); err != nil {
				return err
			}
			start := off + 1 + shift
			for i := 0; i < size; i++ {
				ref := int(parseInt(data[start : start+t.RefBytes]))
				if err := parseObj(ref); err != nil {
					return err
				}
				start += t.RefBytes
			}
			return h.EndArray()

		case 12: // set
			size, shift := sizeAndShift(tag, data[off+1:])
			if err := h.BeginSet(size); err != nil {
				return err
			}
			start := off + 1 + shift
			for i := 0; i < size; i++ {
				ref := int(parseInt(data[start : start+t.RefBytes]))
				if err := parseObj(ref); err != nil {
					return err
				}
				start += t.RefBytes
			}
			return h.EndSet()

		case 13: // dict
			size, shift := sizeAndShift(tag, data[off+1:])
			if err := h.BeginDict(size); err != nil {
				return err
			}
			keyStart := off + 1 + shift
			valStart := keyStart + (size * t.RefBytes)
			for i := 0; i < size; i++ {
				kref := int(parseInt(data[keyStart : keyStart+t.RefBytes]))
				if err := parseObj(kref); err != nil {
					return err
				}
				keyStart += t.RefBytes

				vref := int(parseInt(data[valStart : valStart+t.RefBytes]))
				if err := parseObj(vref); err != nil {
					return err
				}
				valStart += t.RefBytes
			}
			return h.EndDict()
		}
		return fmt.Errorf("unrecognized tag %02x", tag)
	}

	return parseObj(t.RootObject)
}

type trailer struct {
	OffsetBytes int
	RefBytes    int
	NumObjects  int
	RootObject  int
	OffsetTable int
}

func (t *trailer) needBytes() int { return t.OffsetBytes * t.NumObjects }
func (t *trailer) tableEnd() int  { return t.OffsetTable + t.needBytes() }

// parseTrailer unpacks the trailer.
// Precondition: len(data) == 32
func parseTrailer(data []byte) *trailer {
	return &trailer{
		OffsetBytes: int(data[6]),
		RefBytes:    int(data[7]),
		NumObjects:  int(binary.BigEndian.Uint64(data[8:])),
		RootObject:  int(binary.BigEndian.Uint64(data[16:])),
		OffsetTable: int(binary.BigEndian.Uint64(data[24:])),
	}
}

func parseInt(data []byte) (v int64) {
	for _, b := range data {
		v = (v << 8) | int64(b)
	}
	return
}

func parseFloat(data []byte) float64 {
	return math.Float64frombits(uint64(parseInt(data)))
}

func sizeAndShift(tag byte, data []byte) (nb, offset int) {
	nb = int(tag & 0xf)
	if nb == 15 {
		size := 1 << int(data[0]&0xf)
		nb = int(parseInt(data[1 : 1+size]))
		offset = 1 + size
	}
	return
}
