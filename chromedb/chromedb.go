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
	"database/sql"
	"fmt"
	"runtime"
	"time"

	"github.com/creachadair/cookies"
)

const (
	readCookiesStmt = `
SELECT 
  rowid, name, value, encrypted_value, host_key, path,
  expires_utc, creation_utc,
  is_secure, is_httponly, samesite
FROM cookies;`

	writeCookieStmt = `
UPDATE cookies SET
  name = $name,
  %[1]s = $value,
  host_key = $host,
  path = $path,
  expires_utc = $expires,
  creation_utc = $created,
  is_secure = $secure,
  is_httponly = $httponly,
  samesite = $samesite
WHERE rowid = $rowid;`

	dropCookieStmt = `DELETE FROM cookies WHERE rowid = $rowid;`

	// The Chrome timestamp epoch in seconds, 1601-01-01T00:00:00Z.
	chromeEpoch = 11644473600
)

// Open opens the Chrome cookie database at the specified path.
func Open(path string, opts *Options) (*Store, error) {
	db, err := sql.Open(opts.driver(), path)
	if err != nil {
		return nil, err
	}
	return &Store{
		db:  db,
		key: opts.encryptionKey(),
	}, nil
}

// Options provide optional settings for opening a Chrome cookie database.
// A nil *Options is ready for use, and provides empty values.
type Options struct {
	Passphrase string // the passphrase for encrypted values

	// The number of PBKDF2 iterations to use when converting the passphrase
	// into an encryption key. If ≤ 0, use a default based on runtime.GOOS.
	Iterations int
}

// encryptionKey returns the encryption key generated from o, or nil.
func (o *Options) encryptionKey() []byte {
	if o == nil || o.Passphrase == "" {
		return nil
	}
	iter := o.Iterations
	if iter <= 0 {
		switch runtime.GOOS {
		case "darwin":
			iter = 1003
		default:
			iter = 1
		}
	}
	return encryptionKey(o.Passphrase, iter)
}

func (*Options) driver() string { return "sqlite" }

// A Store connects to a collection of cookies stored in an SQLite database
// using the Google Chrome cookie schema.
type Store struct {
	db  *sql.DB
	key []byte // encryption key, or nil
}

// Scan satisfies part of the cookies.Store interface.
func (s *Store) Scan(f cookies.ScanFunc) error {
	cs, err := s.readCookies()
	if err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, c := range cs {
		act, err := f(c)
		if err != nil {
			return err
		}
		switch act {
		case cookies.Keep:
			continue

		case cookies.Update:
			if err := s.writeCookie(tx, c); err != nil {
				return err
			}
		case cookies.Discard:
			if err := s.dropCookie(tx, c); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown action %v", act)
		}
	}
	return tx.Commit()
}

// Commit satisfies part of the cookies.Store interface.
// In this implementation it is a no-op without error.
func (s *Store) Commit() error { return nil }

// readCookies reads all the cookies in the database.
func (s *Store) readCookies() ([]*Cookie, error) {
	rows, err := s.db.Query(readCookiesStmt)
	if err != nil {
		return nil, err
	}

	var cs []*Cookie
	for rows.Next() {
		var rowID, expiresUTC, creationUTC, isSecure, isHTTPOnly, sameSite int64
		var name, value, hostKey, path string
		var encValue []byte
		if err := rows.Scan(&rowID, &name, &value, &encValue, &hostKey, &path,
			&expiresUTC, &creationUTC, &isSecure, &isHTTPOnly, &sameSite); err != nil {
			rows.Close()
			return nil, err
		}

		// If the value is empty, check for an encrypted value.
		if value == "" && len(encValue) != 0 {
			// If we don't have an encryption key, mark the value.
			if len(s.key) == 0 {
				value = "[ENCRYPTED]"
			} else {
				dec, err := decryptValue(s.key, encValue)
				if err != nil {
					return nil, fmt.Errorf("decrypting value: %w", err)
				}
				value = string(dec)
			}
		}

		cs = append(cs, &Cookie{
			C: cookies.C{
				Name:    name,
				Value:   value,
				Domain:  hostKey,
				Path:    path,
				Expires: timestampToTime(expiresUTC),
				Created: timestampToTime(creationUTC),
				Flags: cookies.Flags{
					Secure:   isSecure != 0,
					HTTPOnly: isHTTPOnly != 0,
				},
				SameSite: decodeSitePolicy(sameSite),
			},
			rowID: rowID,
		})
	}
	return cs, nil
}

// dropCookie deletes c from the database.
func (s *Store) dropCookie(tx *sql.Tx, c *Cookie) error {
	_, err := tx.Exec(dropCookieStmt, sql.Named("rowid", c.rowID))
	return err
}

// writeCookie writes the current state of c to the store.
func (s *Store) writeCookie(tx *sql.Tx, c *Cookie) error {
	var column, query string
	var value any
	if len(s.key) == 0 {
		column = "value"
		value = c.Value
	} else if enc, err := encryptValue(s.key, []byte(c.Value)); err != nil {
		return fmt.Errorf("encrypting value: %w", err)
	} else {
		column = "encrypted_value"
		value = enc
	}
	query = fmt.Sprintf(writeCookieStmt, column)

	_, err := tx.Exec(query,
		sql.Named("rowid", c.rowID),
		sql.Named("name", c.Name),
		sql.Named("host", c.Domain),
		sql.Named("path", c.Path),
		sql.Named("expires", timeToTimestamp(c.Expires)),
		sql.Named("created", timeToTimestamp(c.Created)),
		sql.Named("secure", boolToInt(c.Flags.Secure)),
		sql.Named("httponly", boolToInt(c.Flags.HTTPOnly)),
		sql.Named("samesite", encodeSitePolicy(c.SameSite)),
		sql.Named("value", value),
	)
	return err
}

// A Cookie represents a single cookie from a Chrome database.
//
// Values are automatically encrypted and decrypted if the store has an
// encryption key. If no decryption key is provided, encrypted values are
// represented by a Value with string "[ENCRYPTED]"; if an invalid decryption
// key is given, an error is reported.
type Cookie struct {
	cookies.C

	rowID int64
}

// Get satisfies part of the cookies.Editor interface.
func (c *Cookie) Get() cookies.C { return c.C }

// Set satisfies part of the cookies.Editor interface.
func (c *Cookie) Set(o cookies.C) error { c.C = o; return nil }

// decodeSitePolicy maps a Chrome SameSite policy to the generic enum.
func decodeSitePolicy(v int64) cookies.SameSite {
	switch v {
	case 0:
		return cookies.None
	case 1:
		return cookies.Lax
	case 2:
		return cookies.Strict
	default:
		return cookies.Unknown
	}
}

// encodeSitePoicy maps a generic SameSite policy to the Chrome enum.
func encodeSitePolicy(p cookies.SameSite) int64 {
	switch p {
	case cookies.None:
		return 0
	case cookies.Lax:
		return 1
	case cookies.Strict:
		return 2
	default:
		return -1 // unspecified
	}
}

// timestampToTime converts a value in microseconds sincde the Chrome epoch to
// a time in UTC.
func timestampToTime(usec int64) time.Time {
	sec := usec/1e6 - chromeEpoch
	nano := (usec % 1e6) * 1000
	return time.Unix(sec, nano).In(time.UTC)
}

// timeToTimestamp conversts a time value to microseconds since the Chrome epoch.
func timeToTimestamp(t time.Time) int64 {
	sec := t.Unix() + chromeEpoch
	usec := int64(t.Nanosecond()) / 1000
	return sec*1e6 + usec
}

// boolToInt converts a bool to an int64 for storage in SQLite.
func boolToInt(v bool) int64 {
	if v {
		return 1
	}
	return 0
}
