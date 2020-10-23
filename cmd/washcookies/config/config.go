// Package config parses the text config file format forthe washcookies tool.
//
// Blank lines and comments prefixed by "#" are ignored, except as described
// under "Files" below.  Otherwise each non-blank line specifies a rule in the
// following format:
//
//   <f>{<sep><field><op><arg>}+
//
//   f     -- "+" for Allow, "-" for Deny, "!" for Keep
//   sep   -- the separator character for criteria
//   field -- the name of a cookie field (see "Fields")
//   op    -- a comparison operator (see "Operators")
//   arg   -- an argument for comparison (possibly empty)
//
// Files
//
// Comment lines that begin with "#=" are treated as the pathnames of files to
// process. Shell variables such as $HOME are expanded.
//
// Fields
//
// Each cookie has the following fields:
//
//   domain -- the host or domain for which the cookie is delivered
//   path   -- the path for which the cookie is delivered
//   name   -- the name of the cookie
//   value  -- the content of the cookie
//
// Operators
//
// The operators are:
//
//   =  -- case-insensitive string equality
//   ?  -- test for key existence in the cookie
//   ~  -- regular expression search (RE2)
//   @  -- domain-name string matching
//
// Any operator may be prefixed with '!' to negate the sense of the comparison.
// If the key and operator are omitted, "domain" and "@" are assumed.  The "@"
// operator does case-insensitive string comparison, but if the argument starts
// with a period "." then it matches if the argument is a suffix of the value.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/creachadair/cookies"
	"github.com/creachadair/cookies/bincookie"
	"github.com/creachadair/cookies/chromedb"
)

// OpenStore opens a cookie store for the specified path. The type of the
// contents is inferred from the filename.
func OpenStore(path string) (cookies.Store, error) {
	if filepath.Ext(path) == ".binarycookies" {
		return bincookie.Open(path)
	}
	p := strings.ToLower(path)
	if strings.Contains(p, "google") && filepath.Base(p) == "cookies" {
		return chromedb.Open(path, nil)
	}
	return nil, errors.New("unknown file type")
}

// Config represents the contents of a configuration file.
type Config struct {
	Files []string // any #= file lines
	Rules []Rule
}

// Match returns a slice of rules matching the specified cookie, or nil if no
// rules match.
func (c *Config) Match(ck cookies.C) []Rule {
	var out []Rule
	for _, r := range c.Rules {
		if r.Match(ck) {
			out = append(out, r)
		}
	}
	return out
}

// A Rule is a single rule.
type Rule struct {
	Tag     string // one of "+", "-", "!"
	Sep     string
	Clauses []Clause
}

// Match reports whether r matches the given cookie.
func (r Rule) Match(ck cookies.C) bool {
	for _, c := range r.Clauses {
		if !c.Match(ck) {
			return false
		}
	}
	return true
}

// A Clause is a single term of a rule.
type Clause struct {
	Field string // one of "domain", "path", "name", "value"
	Op    string // one of "=", "?", "~", "@" or their negation
	Arg   string // the RHS of the comparison

	// If Op is "~" or "!~", Expr is the compiled regular expression
	// corresponding to Arg. For other operators Expr == nil.
	Expr *regexp.Regexp
}

// Match reports whether c matches the corresponding field of ck.
func (c Clause) Match(ck cookies.C) bool {
	needle := fieldValue(c.Field, ck)
	op := strings.TrimPrefix(c.Op, "!")
	want := op == c.Op
	switch op {
	case "=":
		return (needle == c.Arg) == want
	case "?":
		return (needle != "") == want
	case "~":
		return c.Expr.MatchString(needle) == want
	case "@":
		return domainMatch(needle, c.Arg) == want
	}
	panic("unexpected operator")
}

func domainMatch(domain, pattern string) bool {
	// compare strings case-insensitively
	domain = strings.ToLower(domain)
	pattern = strings.ToLower(pattern)

	// pattern .foo.bar matches foo.bar and any.foo.bar
	if strings.HasPrefix(pattern, ".") {
		return domain == pattern[1:] || strings.HasSuffix(domain, pattern)
	}
	// pattern foo.bar matches just foo.bar
	return domain == pattern
}

func fieldValue(key string, ck cookies.C) string {
	switch key {
	case "name":
		return ck.Name
	case "value":
		return ck.Value
	case "domain":
		return ck.Domain
	case "path":
		return ck.Path
	default:
		return ""
	}
}

// Open opens and parses the configuration file at path.
func Open(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	buf := bufio.NewScanner(f)
	var lnum int
	for buf.Scan() {
		lnum++
		line := strings.TrimSpace(buf.Text())
		if line == "" {
			continue // skip blanks
		} else if strings.HasPrefix(line, "#=") {
			cfg.Files = append(cfg.Files, line[2:])
			continue
		} else if line[0] == '#' {
			continue // skip comments
		}
		rule, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lnum, err)
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	return &cfg, buf.Err()
}

func parseRule(line string) (Rule, error) {
	if len(line) < 2 {
		return Rule{}, errors.New("invalid rule prefix")
	}
	tag, sep := line[:1], line[1:2]
	if tag != "+" && tag != "-" && tag != "!" {
		return Rule{}, fmt.Errorf("invalid rule tag %q", tag)
	}
	out := Rule{Tag: tag, Sep: sep}
	for _, arg := range strings.Split(line[2:], sep) {
		c, err := parseClause(arg)
		if err != nil {
			return out, fmt.Errorf("invalid clause: %w", err)
		}
		switch c.Field {
		case "domain", "path", "name", "value":
			// OK, valid field name
		default:
			return out, fmt.Errorf("unknown field %q", c.Field)
		}
		out.Clauses = append(out.Clauses, c)
	}
	return out, nil
}

var ruleOp = regexp.MustCompile(`^(\w+)(!?[=~@?])`)

func parseClause(arg string) (Clause, error) {
	m := ruleOp.FindStringSubmatch(arg)
	if m == nil {
		return Clause{Field: "domain", Op: "@", Arg: arg}, nil
	}
	out := Clause{
		Field: m[1],
		Op:    m[2],
		Arg:   arg[len(m[0]):],
	}
	if out.Op == "~" || out.Op == "!~" {
		r, err := regexp.Compile(out.Arg)
		if err != nil {
			return out, fmt.Errorf("invalid regexp: %w", err)
		}
		out.Expr = r
	}
	return out, nil
}
