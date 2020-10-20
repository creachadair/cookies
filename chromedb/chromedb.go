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

// Package chromedb supports reading and modifying a Chrome cookies database.
package chromedb

import (
	"encoding/hex"
	"fmt"
	"time"

	"crawshaw.io/sqlite"
	"github.com/creachadair/cookies"
)

const (
	readCookiesStmt = `
SELECT 
  rowid, name, value, encrypted_value, host_key, path,
  expires_utc, creation_utc,
  is_secure, is_httponly
FROM cookies;`

	writeCookieStmt = `
UPDATE cookies SET
  name = $name,
  %[1]s = %[2]s,
  host_key = $host,
  path = $path,
  expires_utc = $expires,
  creation_utc = $created,
  is_secure = $secure,
  is_httponly = $httponly
WHERE rowid = $rowid;`

	dropCookieStmt = `DELETE FROM cookies WHERE rowid = $rowid;`

	// The Chrome timestamp epoch in seconds, 1601-01-01T00:00:00Z.
	chromeEpoch = 11644473600
)

/*
  Schema:

  CREATE TABLE cookies (
     creation_utc     INTEGER  NOT NULL,
     host_key         TEXT     NOT NULL,
     name             TEXT     NOT NULL,
     value            TEXT     NOT NULL,
     path             TEXT     NOT NULL,
     expires_utc      INTEGER  NOT NULL,
     is_secure        INTEGER  NOT NULL,
     is_httponly      INTEGER  NOT NULL,
     last_access_utc  INTEGER  NOT NULL,
     has_expires      INTEGER  NOT NULL DEFAULT  1,
     is_persistent    INTEGER  NOT NULL DEFAULT  1,
     priority         INTEGER  NOT NULL DEFAULT  1,
     encrypted_value  BLOB              DEFAULT '',
     samesite         INTEGER  NOT NULL DEFAULT  -1,
     source_scheme    INTEGER  NOT NULL DEFAULT  0,

     UNIQUE (host_key, name, path)
);
*/

// Open opens the Chrome cookie database at the specified path.
func Open(path string) (*Store, error) {
	conn, err := sqlite.OpenConn(path, sqlite.SQLITE_OPEN_READWRITE)
	if err != nil {
		return nil, err
	}
	return &Store{conn: conn}, nil
}

// A Store connects to a collection of cookies stored in an SQLite database
// using the Google Chrome cookie schema.
type Store struct {
	conn *sqlite.Conn
}

// Scan satisfies part of the cookies.Store interface.
func (s *Store) Scan(f cookies.ScanFunc) (err error) {
	cs, err := s.readCookies()
	if err != nil {
		return err
	}

	defer s.begin(&err)()
	for _, c := range cs {
		act, err := f(c)
		if err != nil {
			return err
		}
		switch act {
		case cookies.Keep:
			continue
		case cookies.Update:
			if err := s.writeCookie(c); err != nil {
				return err
			}
		case cookies.Discard:
			if err := s.dropCookie(c); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown action %v", act)
		}
	}
	return nil
}

// Commit satisfies part of the cookies.Store interface.
// In this implementation it is a no-op without error.
func (s *Store) Commit() error { return nil }

// readCookies reads all the cookies in the database.
func (s *Store) readCookies() ([]*Cookie, error) {
	stmt, err := s.conn.Prepare(readCookiesStmt)
	if err != nil {
		return nil, err
	}
	stmt.Reset()

	var cs []*Cookie
	for {
		ok, err := stmt.Step()
		if err != nil {
			return nil, err
		} else if !ok {
			break
		}
		isEncrypted := false
		val := stmt.GetText("value")
		if val == "" {
			buf := make([]byte, stmt.GetLen("encrypted_value"))
			stmt.GetBytes("encrypted_value", buf)
			val = string(buf)
			isEncrypted = true
		}
		cs = append(cs, &Cookie{
			C: cookies.C{
				Name:    stmt.GetText("name"),
				Value:   val,
				Domain:  stmt.GetText("host_key"),
				Path:    stmt.GetText("path"),
				Expires: timestampToTime(stmt.GetInt64("expires_utc")),
				Created: timestampToTime(stmt.GetInt64("creation_utc")),
				Flags: cookies.Flags{
					Secure:   stmt.GetInt64("is_secure") != 0,
					HTTPOnly: stmt.GetInt64("is_httponly") != 0,
				},
			},

			isEncrypted: isEncrypted,
			rowID:       stmt.GetInt64("rowid"),
		})
	}
	return cs, nil
}

// begin begins a transaction and returns a function to finish that
// transaction. If *err == nil, the transaction is committed; otherwise the
// transaction is rolled back.
func (s *Store) begin(err *error) func() {
	stmt := s.conn.Prep("BEGIN TRANSACTION;")
	stmt.Step()
	return func() {
		if *err == nil {
			s.conn.Prep("COMMIT;").Step()
		} else {
			s.conn.Prep("ROLLBACK;").Step()
		}
	}
}

// dropCookie deletes c from the database.
func (s *Store) dropCookie(c *Cookie) error {
	stmt, err := s.conn.Prepare(dropCookieStmt)
	if err != nil {
		return err
	}
	stmt.Reset()
	stmt.SetInt64("$rowid", c.rowID)
	_, err = stmt.Step()
	return err
}

func (s *Store) writeCookie(c *Cookie) error {
	var query string
	if c.isEncrypted {
		query = fmt.Sprintf(writeCookieStmt, "encrypted_value",
			"X'"+hex.EncodeToString([]byte(c.Value))+"'")
	} else {
		query = fmt.Sprintf(writeCookieStmt, "value", "$value")
	}
	stmt, err := s.conn.Prepare(query)
	if err != nil {
		return err
	}
	stmt.Reset()
	stmt.SetInt64("$rowid", c.rowID)
	stmt.SetText("$name", c.Name)
	stmt.SetText("$host", c.Domain)
	stmt.SetText("$path", c.Path)
	stmt.SetInt64("$expires", timeToTimestamp(c.Expires))
	stmt.SetInt64("$created", timeToTimestamp(c.Created))
	stmt.SetInt64("$secure", boolToInt(c.Flags.Secure))
	stmt.SetInt64("$httponly", boolToInt(c.Flags.HTTPOnly))
	if !c.isEncrypted {
		stmt.SetText("$value", c.Value)
	}
	_, err = stmt.Step()
	return err
}

// A Cookie represents a single cookie from a Chrome database.
type Cookie struct {
	cookies.C

	isEncrypted bool
	rowID       int64
}

// IsEncrypted reports whether the Value field is encrypted.
func (c *Cookie) IsEncrypted() bool { return c.isEncrypted }

// Get satisfies part of the cookies.Editor interface.
func (c *Cookie) Get() *cookies.C { return &c.C }

// Set satisfies part of the cookies.Editor interface.
func (c *Cookie) Set(o *cookies.C) error { c.C = *o; return nil }

func timestampToTime(usec int64) time.Time {
	sec := usec/1e6 - chromeEpoch
	nano := (usec % 1e6) * 1000
	return time.Unix(sec, nano).In(time.UTC)
}

func timeToTimestamp(t time.Time) int64 {
	sec := t.Unix() + chromeEpoch
	usec := int64(t.Nanosecond()) / 1000
	return sec*1e6 + usec
}

func boolToInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
