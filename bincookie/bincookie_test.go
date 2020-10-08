package bincookie_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/creachadair/cookies/bincookie"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestRoundTrip(t *testing.T) {
	base := time.Unix(1602034364, 0)

	f := &bincookie.File{
		Pages: []*bincookie.Page{{
			Cookies: []*bincookie.Cookie{{
				Flags:   bincookie.Flag_Secure,
				URL:     "example.com",
				Path:    "/foo",
				Name:    "letter",
				Value:   "alpha",
				Created: base,
				Expires: base.Add(3 * 24 * time.Hour),
			}},
		}, {
			Cookies: []*bincookie.Cookie{{
				URL:     ".google.com",
				Name:    "number",
				Value:   "seventeen",
				Created: base,
				Expires: base.Add(12 * time.Hour),
			}, {
				URL:   ".fancybank.org",
				Path:  "/account",
				Name:  "login",
				Value: "freezetag",
				Flags: bincookie.Flag_HTTPOnly | bincookie.Flag_Secure,
			}},
		}},
		Policy: []byte(bincookie.DefaultPolicy),
	}

	var buf bytes.Buffer
	if nw, err := f.WriteTo(&buf); err != nil {
		t.Fatalf("Write failed: %v", err)
	} else {
		t.Logf("Wrote %d bytes; checksum=%04x", nw, f.Checksum)
	}

	g, err := bincookie.ParseFile(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}
	t.Logf("Read OK, checksum=%04x", g.Checksum)

	opts := cmpopts.IgnoreUnexported(bincookie.File{}, bincookie.Cookie{}, bincookie.Page{})
	if diff := cmp.Diff(f, g, opts); diff != "" {
		t.Errorf("Round trip failed: (-want, +got)\n%s", diff)
	}
}
