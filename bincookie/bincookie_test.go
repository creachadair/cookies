// Copyright 2020 Michael J. Fromberger. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bincookie_test

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/creachadair/cookies"
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

	// Read the raw bytes of the file for comparison purposes.
	data, err := os.ReadFile(*inputFile)
	if err != nil {
		t.Fatalf("Reading input: %v", err)
	}
	t.Logf("Read %d bytes from %q", len(data), *inputFile)

	// Open a scanner on the same file.
	s, err := bincookie.Open(*inputFile)
	if err != nil {
		t.Fatalf("Opening store: %v", err)
	}

	// Capture output to a buffer, and copy to a file if -output is set.
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

	// Exercise the Scan method of the store.
	var count int
	if err := s.Scan(func(e cookies.Editor) (cookies.Action, error) {
		count++
		c := e.Get()
		t.Logf("Cookie %d: domain=%q, name=%q, value=%q, samesite=%v, created=%v | expires=%v",
			count, c.Domain, c.Name, trimValue(c.Value), c.SameSite, c.Created, c.Expires)
		return cookies.Keep, nil
	}); err != nil {
		t.Errorf("Scan failed: %v", err)
	}
	t.Logf("Scanned %d cookies", count)

	// Serialize the results to make sure we don't lose any data.
	nw, err := s.WriteTo(w)
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
				Flags:   bincookie.FlagSecure,
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
				Flags: bincookie.FlagHTTPOnly | bincookie.FlagSecure,
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

func trimValue(s string) string {
	if len(s) < 70 {
		return s
	}
	return s[:60] + fmt.Sprintf("[...%d more]", len(s)-70)
}
