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

// Program washcookies cleans up browser cookies based on a policy.
//
// Edit stored web cookies to discard any cookies not permitted by a
// user-specified policy. A policy consists of three types of rules: Allow,
// Deny, and Keep.
//
// If a cookie is matched by any Keep rule, it is explicitly retained.
// Otherwise, if any Deny rule matches the cookie, it is discarded.
// Otherwise, if no Allow rule matches the cookie, it is discarded.
//
// For a description of the configuration file format, see
//   https://godoc.org/github.com/creachadair/cookies/cmd/washcookies/config
//
// Examples
//
// Accept all cookies from host names ending in "banksite.com":
//
//    + .banksite.com
//
// Reject all Google Analytics cookies:
//
//    - name~^__utm[abvz]$
//
// Accept cookies from somehost.com, but not "foo.somehost.com":
//
//    + .somehost.com domain!=foo.somehost.com
//
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/creachadair/cookies"
	"github.com/creachadair/cookies/cmd/washcookies/config"
)

var (
	configPath = flag.String("config", "$HOME/.cookierc", "Configuration file path (required)")
	doDryRun   = flag.Bool("dry-run", false, "Process inputs but do not apply the changes")
	doVerbose  = flag.Bool("v", false, "Verbose logging")

	tw = tabwriter.NewWriter(os.Stderr, 4, 8, 1, ' ', 0)
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %s [options] [cookie-file...]

Edit browser cookies to remove any that do not match the specified
policy rules. For a description of the configuration file format, see:

  https://godoc.org/github.com/creachadair/cookies/cmd/washcookies/config

If cookie files are named on the commmand line, they are processed
in preference to any files named in the configuration file.

Options:
`, filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	// Load the configuration file.
	if *configPath == "" {
		log.Fatal("You must provide a non-empty -config path")
	}
	cfg, err := config.Open(os.ExpandEnv(*configPath))
	if err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// If the user specified non-flag arguments, use them instead of the file
	// list from the configuration file.
	if flag.NArg() != 0 {
		if len(cfg.Files) != 0 {
			fmt.Fprintf(os.Stderr, "🚨 Skipping %d inputs listed in the config file\n", len(cfg.Files))
		}
		cfg.Files = flag.Args()
	}

	if *doDryRun {
		fmt.Fprint(os.Stderr, "☂️  This is a dry run; no changes will be made\n\n")
	}

	for _, path := range cfg.Files {
		path = os.ExpandEnv(path)
		s, err := config.OpenStore(path)
		if os.IsNotExist(err) {
			log.Printf("Skipping %q, file not found", path)
			continue
		} else if err != nil {
			log.Fatalf("Opening %q: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "Scanning %q\n", path)

		var nKept, nDiscarded int
		if err := s.Scan(func(e cookies.Editor) (cookies.Action, error) {
			ck := e.Get()
			var allowReason, denyReason string
			var allow, deny bool
			for _, rule := range cfg.Match(ck) {
				switch rule.Tag {
				case "!":
					nKept++
					vlog(message("✨", ck, rule.Reason))
					return cookies.Keep, nil
				case "-":
					deny = true
					denyReason = rule.Reason
				case "+":
					allow = true
					allowReason = rule.Reason
				}
			}
			if deny || !allow {
				nDiscarded++
				fmt.Fprint(tw, message("🚫", ck, denyReason))
				if *doDryRun {
					return cookies.Keep, nil
				}
				return cookies.Discard, nil
			}
			nKept++
			vlog(message("🆗", ck, allowReason))
			return cookies.Keep, nil
		}); err != nil {
			log.Fatalf("Scanning %q: %v", path, err)
		} else if err := s.Commit(); err != nil {
			log.Fatalf("Committing %q: %v", path, err)
		}
		tw.Flush()
		fmt.Fprintf(os.Stderr, ">> TOTAL %d cookies; kept %d, discarded %d\n\n",
			nKept+nDiscarded, nKept, nDiscarded)
	}
}

func vlog(msg string) {
	if *doVerbose {
		fmt.Fprint(tw, msg)
	}
}

func message(emo string, ck cookies.C, reason string) string {
	args := []string{" " + emo, ck.Domain, ck.Name, reason}
	return strings.Join(args, "\t") + "\n"
}
