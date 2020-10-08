package bplist_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

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
	const want = `V"00"1<"NSHTTPCookieAcceptPolicy"2>`
	if got := buf.String(); got != want {
		t.Errorf("Parse result: got %s, want %s", got, want)
	}
}

type testHandler struct {
	buf *bytes.Buffer
}

func (h testHandler) Version(s string) error { fmt.Fprintf(h.buf, "V%q", s); return nil }
func (h testHandler) Null() error            { h.buf.WriteString("null"); return nil }
func (h testHandler) Bool(tf bool) error     { fmt.Fprint(h.buf, tf); return nil }
func (h testHandler) Int(z int64) error      { fmt.Fprintf(h.buf, "%d", z); return nil }
func (h testHandler) Float(v float64) error  { fmt.Fprint(h.buf, v); return nil }
func (h testHandler) Time(t time.Time) error { fmt.Fprint(h.buf, t); return nil }
func (h testHandler) Bytes(v []byte) error   { fmt.Fprintf(h.buf, "[%d]", len(v)); return nil }
func (h testHandler) String(v string) error  { fmt.Fprintf(h.buf, "%q", v); return nil }
func (h testHandler) UID(v []byte) error     { fmt.Fprintf(h.buf, "U[%d]", len(v)); return nil }
func (h testHandler) BeginArray(n int) error { fmt.Fprintf(h.buf, "%d[", n); return nil }
func (h testHandler) EndArray() error        { h.buf.WriteString("]"); return nil }
func (h testHandler) BeginDict(n int) error  { fmt.Fprintf(h.buf, "%d<", n); return nil }
func (h testHandler) EndDict() error         { h.buf.WriteString(">"); return nil }
func (h testHandler) BeginSet(n int) error   { fmt.Fprintf(h.buf, "%d{", n); return nil }
func (h testHandler) EndSet() error          { h.buf.WriteString("}"); return nil }
