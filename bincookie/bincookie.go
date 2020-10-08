// Package bincookie supports reading and modifying Apple binary cookie files.
//
// Browsers and other macOS applications use the NSHTTPCookieStorage API to
// store cookies. The API writes .binarycookies files in a specialized binary
// format. This library permits those files to be read and written.
//
// To parse a file:
//
//     f, err := bincookie.ParseFile(fileData)
//
// A file contains a number of pages, each of which contains one or more cookie
// records. A file can be modified and then written back:
//
//     hack(f)
//     if _, err := f.WriteTo(outputFile); err != nil {
//        log.Fatalf("Writing cookies: %v", err)
//     }
//
// The Checksum field of a file is populated when the file is parsed, and is
// updated when the file is written. When constructing a file from scratch, it
// is safe to leave the chedksum set to zero; after a successful write, the
// file is updated with the correct checksum value.
//
// File format
//
// The binary file format has the following structure:
//
//   Bytes | Format     | Description
//  -------|------------|----------------------------------------------
//   4     | text       | magic number ('cook')
//   4     | uint32 BE  | page count (np)
//  *4 [i] | uint32 BE  | page i data size S, bytes; *repeat np times
//  *S [i] | bytes      | page i contents; *repeat np times
//   4     | uint32 BE  | checksum (see below)
//   4     | bytes      | footer (07 17 20 05 hex)
//   4     | uint32 BE  | policy size, bytes (ps)
//   ps    | bytes      | binary NSHTTPCookieAcceptPolicy message
//
// Each page has the following format:
//
//   Bytes | Format     | Description
//  -------|------------|----------------------------------------------
//   4     | bytes      | magic number (00 00 01 00 hex)
//   4     | uint32 LE  | cookie count (nc)
//  *4 [i] | uint32 LE  | cookie i offset; *repeat nc times
//   4     | uint32=0   | footer (value 0)
//
// Each cookie has the following format:
//
//   Bytes | Format     | Description
//  -------|------------|----------------------------------------------
//   4     | uint32 LE  | cookie record size, bytes (incl. size field)
//   4     | uint32 LE  | unknown meaning; usually zero
//   4     | uint32 LE  | flag bitmap (1=secure, 4=httpOnly)
//   4     | uint32 LE  | unknown meaning; usually zero
//   4     | uint32 LE  | offset of URL string
//   4     | uint32 LE  | offset of name string
//   4     | uint32 LE  | offset of path string
//   4     | uint32 LE  | offset of value string
//   8     | uint64=0   | end marker (value 0)
//   8     | float64 LE | expires; seconds since 01-Jan-2001 00:00:00 UTC
//   8     | float64 LE | created; seconds since 01-Jan-2001 00:00:00 UTC
//   nd    | strings    | NUL-terminated strings for field values
//
// The field values for a cookie may be packed in any order.
//
// Checksum
//
// The checksum is computed over the binary encoding of each page.  The
// checksum for a page is the integer sum of the bytes at offset multiples of 4
// (0, 4, 8, ...). The checksum of the file is the sum of the page checksums.
//
package bincookie

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
)

const (
	macEpoch    = 978307200 // 01-Jan-2001
	fileMagic   = "cook"
	pageMagic   = "\x00\x00\x01\x00"
	fileTrailer = "\x07\x17\x20\x05"

	// DefaultPolicy is the default cookie acccept policy property list used
	// when writing a *File that does not set one explicitly.
	//
	// This is the binary property list encoding of NSHTTPCookieAcceptPolicy: 2.
	//
	//   0: Always
	//   1: Never
	//   2: OnlyFromMainDocumentDomain (default)
	//
	DefaultPolicy = "bplist00\xd1\x01\x02_\x10\x18NSHTTPCookieAcceptPolicy\x10" +
		"\x02\x08\x0b&\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00" +
		"\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00("
)

// A File represents the complete contents of a bincookie file.
type File struct {
	Pages []*Page

	// The checksum of the file. When reading, this is populated from the stored
	// value in the input. Writing the File will update the checksum.
	Checksum uint32

	// The cookie acceptance policy, as a binary-format property list.  If
	// empty, a standard policy will be written for OnlyFromMainDocumentDomain.
	Policy []byte
}

// WriteTo encodes f in binary format to w.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	buf.WriteString(fileMagic)
	writeBig32(&buf, uint32(len(f.Pages)))
	pos := buf.Len()                       // position of next length
	addPadding(&buf, "xxxx", len(f.Pages)) // length placeholders

	var checksum uint32
	for _, page := range f.Pages {
		nw, err := page.WriteTo(&buf)
		if err != nil {
			return 0, err
		}
		data := buf.Bytes()
		checksum += pageChecksum(data[len(data)-int(nw):])
		binary.BigEndian.PutUint32(data[pos:], uint32(nw)) // update length
		pos += 4
	}

	f.Checksum = checksum
	writeBig32(&buf, checksum)
	buf.WriteString(fileTrailer)

	p := f.Policy
	if len(p) == 0 {
		p = []byte(DefaultPolicy)
	}
	writeBig32(&buf, uint32(len(p)))
	buf.Write(p)
	return io.Copy(w, &buf)
}

// A Page is a collection of cookies.
type Page struct {
	Cookies []*Cookie
}

// WriteTo encodes p in binary format to w.
func (p *Page) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	buf.WriteString(pageMagic)
	writeLittle32(&buf, uint32(len(p.Cookies)))
	pos := buf.Len()                         // position of next offset
	addPadding(&buf, "xxxx", len(p.Cookies)) // offset placeholders
	writeLittle32(&buf, 0)                   // page trailer

	next := buf.Len() // offset of next page
	for _, cookie := range p.Cookies {
		data := buf.Bytes()
		binary.LittleEndian.PutUint32(data[pos:], uint32(next))
		pos += 4
		if _, err := cookie.WriteTo(&buf); err != nil {
			return 0, err
		}
		next = buf.Len()
	}
	return io.Copy(w, &buf)
}

// A Cookie represents a single cookie.
type Cookie struct {
	Flags   uint32
	URL     string
	Name    string
	Path    string
	Value   string
	Expires time.Time
	Created time.Time

	_unknown1 [4]byte
	_unknown2 [4]byte
}

// WriteTo encodes c in binary format to w.
func (c *Cookie) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	writeLittle32(&buf, 0) // placeholder
	buf.Write(c._unknown1[:])
	writeLittle32(&buf, c.Flags)
	buf.Write(c._unknown2[:])
	pos := buf.Len()            // position of next offset
	addPadding(&buf, "xxxx", 4) // url, name, path, value (order matters)
	addPadding(&buf, "\x00", 8) // end marker
	writeFloat64(&buf, float64(c.Expires.Unix()-macEpoch))
	writeFloat64(&buf, float64(c.Created.Unix()-macEpoch))
	for _, s := range []string{c.URL, c.Name, c.Path, c.Value} { // order matters
		cur := buf.Len()
		data := buf.Bytes()
		binary.LittleEndian.PutUint32(data[pos:], uint32(cur))
		pos += 4
		buf.WriteString(s)
		buf.WriteByte(0)
	}
	data := buf.Bytes()
	binary.LittleEndian.PutUint32(data, uint32(buf.Len()))
	return io.Copy(w, &buf)
}

// Constants for the flags bitmap.
const (
	Flag_Secure   = 1
	Flag_HTTPOnly = 4
)

// ParseFile parses the binary contents of a bincookie file.
func ParseFile(data []byte) (*File, error) {
	if !bytes.HasPrefix(data, []byte(fileMagic)) {
		return nil, errors.New("invalid file magic")
	}

	// Number of pages.
	numPages, err := bigUint32(data, 4)
	if err != nil {
		return nil, err
	}

	// Page sizes.
	var sizes []int
	cur := 8
	for i := 0; i < int(numPages); i++ {
		size, err := bigUint32(data, cur)
		if err != nil {
			return nil, err
		}
		sizes = append(sizes, int(size))
		cur += 4
	}

	// Page contents.
	var pages []*Page
	for _, size := range sizes {
		if cur+size > len(data) {
			return nil, fmt.Errorf("page truncated at %d", len(data))
		}
		page, err := parsePage(data[cur : cur+size])
		if err != nil {
			return nil, fmt.Errorf("parsing page: %w", err)
		}
		pages = append(pages, page)
		cur += size
	}

	// Checksum.
	fcheck, err := bigUint32(data, cur)
	if err != nil {
		return nil, fmt.Errorf("invalid file checksum: %w", err)
	}
	cur += 4

	// File trailer. Not sure what this is, maybe a version?
	if !bytes.HasPrefix(data[cur:], []byte(fileTrailer)) {
		return nil, errors.New("invalid file trailer")
	}
	cur += len(fileTrailer)

	f := &File{
		Pages:    pages,
		Checksum: fcheck,
	}
	if cur < len(data) {
		// Cookie accept policy, encoded as a binary property list.
		plen, err := bigUint32(data, cur)
		if err != nil {
			return nil, err
		}
		cur += 4
		end := cur + int(plen)
		f.Policy = data[cur:end]
		cur = end
	}
	return f, nil
}

func parsePage(data []byte) (*Page, error) {
	if !bytes.HasPrefix(data, []byte(pageMagic)) {
		return nil, errors.New("invalid page magic")
	}

	// Number of cookies in this page.
	nc, err := littleUint32(data, 4)
	if err != nil {
		return nil, err
	}

	// Start offsets of cookies from the beginning of data.
	var cookies []*Cookie
	cur := 8
	for i := 0; i < int(nc); i++ {
		off, err := littleUint32(data, cur)
		if err != nil {
			return nil, err
		}
		cur += 4

		size, err := littleUint32(data, int(off))
		if err != nil {
			return nil, fmt.Errorf("cookie %d: %w", i+1, err)
		} else if int(off+size) > len(data) {
			return nil, fmt.Errorf("cookie %d: incomplete data at %d", i+1, off)
		}

		c, err := parseCookie(data[off : off+size])
		if err != nil {
			return nil, fmt.Errorf("cookie %d: %w", i+1, err)
		}
		cookies = append(cookies, c)
	}

	// Page trailer
	if t, err := bigUint32(data, cur); err != nil || t != 0 {
		return nil, errors.New("invalid page trailer")
	}
	return &Page{Cookies: cookies}, nil
}

func parseCookie(data []byte) (*Cookie, error) {
	// 0..3 is length; already checked
	// 4..7 is unknown
	flags, err := littleUint32(data, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid flags: %w", err)
	}
	// 12..15 is unknown
	urlPos, err := littleUint32(data, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid URL offset: %w", err)
	}
	namePos, err := littleUint32(data, 20)
	if err != nil {
		return nil, fmt.Errorf("invalid name offset: %w", err)
	}
	pathPos, err := littleUint32(data, 24)
	if err != nil {
		return nil, fmt.Errorf("invalid path offset: %w", err)
	}
	valuePos, err := littleUint32(data, 28)
	if err != nil {
		return nil, fmt.Errorf("invalid value offset: %w", err)
	}
	// 32..39 is an end marker, all zeroes
	expires, err := littleFloat64(data, 40)
	if err != nil {
		return nil, fmt.Errorf("invalid expiration time: %w", err)
	}
	created, err := littleFloat64(data, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid created time: %w", err)
	}
	c := &Cookie{
		Flags:   flags,
		URL:     nulString(data[int(urlPos):]),
		Name:    nulString(data[int(namePos):]),
		Path:    nulString(data[int(pathPos):]),
		Value:   nulString(data[int(valuePos):]),
		Expires: time.Unix(int64(expires)+macEpoch, 0).In(time.UTC),
		Created: time.Unix(int64(created)+macEpoch, 0).In(time.UTC),
	}
	copy(c._unknown1[:], data[4:])
	copy(c._unknown2[:], data[12:])
	return c, nil
}

// bigUint32 reads a big-endian uint32 at position pos of data.
func bigUint32(data []byte, pos int) (uint32, error) {
	if pos+4 > len(data) {
		return 0, fmt.Errorf("incomplete uint32 at %d", pos)
	}
	return binary.BigEndian.Uint32(data[pos:]), nil
}

// littleUint32 reads a little-endian uint32 at position pos of data.
func littleUint32(data []byte, pos int) (uint32, error) {
	if pos+4 > len(data) {
		return 0, fmt.Errorf("incomplete uint32 at %d", pos)
	}
	return binary.LittleEndian.Uint32(data[pos:]), nil
}

// littleFloat64 reads a little-endian float64 at position pos of data.
func littleFloat64(data []byte, pos int) (float64, error) {
	if pos+8 > len(data) {
		return 0, fmt.Errorf("incomplete int64 at %d", pos)
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(data[pos:])), nil
}

// nulString reads a zero-terminated string from a prefix of data.  The result
// excludes the terminating NUL byte.
func nulString(data []byte) string {
	pos := 0
	for pos < len(data) && data[pos] != 0 {
		pos++
	}
	return string(data[:pos])
}

// pageChecksum computes the checksum of a binary encoded page value.
func pageChecksum(data []byte) (sum uint32) {
	for i := 0; i < len(data); i += 4 {
		sum += uint32(data[i])
	}
	return
}

// writeBig32 writes u in big-endian order to w.
func writeBig32(w io.Writer, u uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], u)
	w.Write(buf[:])
}

// writeLittle32 writes u in little-endian order to w.
func writeLittle32(w io.Writer, u uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], u)
	w.Write(buf[:])
}

// writeFloat64 writes f as binary in little-endian order to w.
func writeFloat64(w io.Writer, f float64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], math.Float64bits(f))
	w.Write(buf[:])
}

// addPadding extends buf with n copies of s.
func addPadding(buf *bytes.Buffer, s string, n int) {
	buf.Grow(n * len(s))
	for n > 0 {
		buf.WriteString(s)
		n--
	}
}