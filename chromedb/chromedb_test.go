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

package chromedb_test

import (
	"flag"
	"testing"

	"github.com/creachadair/cookies"
	"github.com/creachadair/cookies/chromedb"

	_ "modernc.org/sqlite"
)

var (
	inputFile = flag.String("input", "", "Input Chrome cookie database")
	dbSecret  = flag.String("passphrase", "", "Passphrase for encrypted values")
	doUpdate  = flag.Bool("update", false, "Update cookies in-place")
)

func TestManual(t *testing.T) {
	if *inputFile == "" {
		t.Skip("Skipping test since no -input is specified")
	}
	s, err := chromedb.Open(*inputFile, &chromedb.Options{
		Passphrase: *dbSecret,
	})
	if err != nil {
		t.Fatalf("Opening database: %v", err)
	}

	var numCookies int
	if err := s.Scan(func(e cookies.Editor) (cookies.Action, error) {
		numCookies++
		c := e.Get()
		t.Logf("-- Cookie %d:\n"+
			"  domain=%q name=%q value=%q\n"+
			"  secure=%v http_only=%v samesite=%v\n"+
			"  created=%v | expires=%v",
			numCookies,
			c.Domain, c.Name, c.Value,
			c.Flags.Secure, c.Flags.HTTPOnly, c.SameSite,
			c.Created, c.Expires,
		)
		if *doUpdate {
			return cookies.Update, nil
		}
		return cookies.Keep, nil
	}); err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if err := s.Commit(); err != nil {
		t.Fatalf("commit failed; %v", err)
	}

	t.Logf("Found %d cookies", numCookies)
}
