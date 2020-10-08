package bincookie_test

import (
	"bytes"
	"flag"
	"io"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/creachadair/cookies/bincookie"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	inputFile  = flag.String("input", "", "Input binarycookies file")
	outputFile = flag.String("output", "", "Output binarycookies file")
)

// Manually verify that a "real" user-provided binarycookies file can be
// round-tripped correctly if no modifications are made.
//
// If an -output file is provided, also write the output there so that it can
// be preserved for later study.
func TestManual(t *testing.T) {
	if *inputFile == "" {
		t.Skip("Skipping test since no -input is specified")
	}
	data, err := ioutil.ReadFile(*inputFile)
	if err != nil {
		t.Fatalf("Reading input: %v", err)
	}
	t.Logf("Read %d bytes from %q", len(data), *inputFile)
	f, err := bincookie.ParseFile(data)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	var buf bytes.Buffer
	var w io.Writer = &buf
	if *outputFile != "" {
		out, err := os.Create(*outputFile)
		if err != nil {
			t.Fatalf("Creating output: %v", err)
		}
		defer func() {
			if err := out.Close(); err != nil {
				t.Fatalf("Closing output: %v", err)
			}
		}()
		w = io.MultiWriter(&buf, out)
	}

	nw, err := f.WriteTo(w)
	if err != nil {
		t.Errorf("Writing output: %v", err)
	} else {
		t.Logf("Wrote %d bytes", nw)
	}

	if diff := cmp.Diff(data, buf.Bytes()); diff != "" {
		t.Errorf("Incorrect output: (-want, +got):\n%s", diff)
	}
}

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
