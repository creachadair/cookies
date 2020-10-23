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
// See the config package for a description of the config file format.
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

	"github.com/creachadair/cookies"
	"github.com/creachadair/cookies/cmd/washcookies/config"
)

var (
	configPath = flag.String("config", "$HOME/.cookierc", "Configuration file path (required)")
	doDryRun   = flag.Bool("dry-run", false, "Process inputs but do not apply the changes")
	doVerbose  = flag.Bool("v", false, "Verbose logging")
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %s [options] [cookie-file...]

Edit browser cookies to remove any that do not match the specified
policy rules.

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
		fmt.Fprint(os.Stderr, "🦺 This is a dry run; no changes will be made\n\n")
	}

	for _, path := range cfg.Files {
		path = os.ExpandEnv(path)
		s, err := config.OpenStore(path)
		if err != nil {
			log.Fatalf("Opening %q: %v", path, err)
		}
		fmt.Fprintf(os.Stderr, "Scanning %q\n", path)

		var nKept, nDiscarded int
		if err := s.Scan(func(e cookies.Editor) (cookies.Action, error) {
			ck := e.Get()
			var keep, allow, deny bool
			for _, rule := range cfg.Match(ck) {
				switch rule.Tag {
				case "+":
					allow = true
				case "-":
					deny = true
				case "!":
					keep = true
				}
			}
			if keep {
				nKept++
				vlog(" ✨ %-30s %s\n", ck.Domain, ck.Name)
				return cookies.Keep, nil
			} else if allow && !deny {
				nKept++
				vlog(" 🆗 %-30s %s\n", ck.Domain, ck.Name)
				return cookies.Keep, nil
			}
			nDiscarded++
			fmt.Fprintf(os.Stderr, " 🚫 %-30s %s\n", ck.Domain, ck.Name)
			if *doDryRun {
				return cookies.Keep, nil
			}
			return cookies.Discard, nil
		}); err != nil {
			log.Fatalf("Scanning %q: %v", path, err)
		} else if err := s.Commit(); err != nil {
			log.Fatalf("Committing %q: %v", path, err)
		}

		fmt.Fprintf(os.Stderr, ">> TOTAL %d cookies; kept %d, discarded %d\n\n",
			nKept+nDiscarded, nKept, nDiscarded)
	}
}

func vlog(msg string, args ...interface{}) {
	if *doVerbose {
		fmt.Fprintf(os.Stderr, msg, args...)
	}
}
