package bplist_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/creachadair/cookies/bplist"
)

func TestBasic(t *testing.T) {
	const testInput = "bplist00\xd1\x01\x02_\x10\x18NSHTTPCookieAcceptPolicy\x10" +
		"\x02\x08\x0b&\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00" +
		"\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00("

	var buf bytes.Buffer
	if err := bplist.Parse([]byte(testInput), testHandler{
		buf: &buf,
	}); err != nil {
		t.Errorf("Parse failed; %v", err)
	}
	const want = `V"00"<dict size=1>(string=NSHTTPCookieAcceptPolicy)(int=2)</dict>`
	if got := buf.String(); got != want {
		t.Errorf("Parse result: got %s, want %s", got, want)
	}
}

type testHandler struct {
	buf *bytes.Buffer
}

func (h testHandler) Version(s string) error {
	fmt.Fprintf(h.buf, "V%q", s)
	return nil
}

func (h testHandler) Element(elt bplist.Type, datum interface{}) error {
	if b, ok := datum.([]byte); ok {
		fmt.Fprintf(h.buf, "(%s=%d bytes)", elt, len(b))
	} else {
		fmt.Fprintf(h.buf, "(%s=%v)", elt, datum)
	}
	return nil
}

func (h testHandler) Open(coll bplist.Collection, n int) error {
	fmt.Fprintf(h.buf, "<%s size=%d>", coll, n)
	return nil
}

func (h testHandler) Close(coll bplist.Collection) error {
	fmt.Fprintf(h.buf, "</%s>", coll)
	return nil
}
