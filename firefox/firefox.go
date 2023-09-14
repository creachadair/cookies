// Copyright 2023 Michael J. Fromberger. All Rights Reserved.
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

// Package firefox supports reading and modifying a Firefox cookies database.
package firefox

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/creachadair/cookies"
)

// Open opens the Firefox cookie database at the specified path.
// If opts == nil, default options are used.
func Open(path string, opts *Options) (*Store, error) {
	db, err := sql.Open(opts.driver(), path)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

// Options are optional settings for a Store.
// A nil *Options is ready for use with default settings.
type Options struct{}

func (*Options) driver() string { return "sqlite" }

// A Store connects to a collection of cookies storeed in an SQLite database
// using the Firefox cookie schema.
type Store struct {
	db *sql.DB
}

// Scan implements part of the cookies.Store interface.
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

// Commit implements part of the cookies.Store interface.
func (s *Store) Commit() error { return nil }

type Cookie struct {
	cookies.C

	id int64
}

// Get implements part of the cookies.Editor interface.
func (c *Cookie) Get() cookies.C { return c.C }

// Set implements part of the cookies.Editor interface.
func (c *Cookie) Set(o cookies.C) error { c.C = o; return nil }

func (s *Store) readCookies() ([]*Cookie, error) {
	rows, err := s.db.Query(`SELECT ` +
		`id, name, value, host, path, expiry, creationTime, isSecure, isHttpOnly, sameSite ` +
		`FROM moz_cookies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cs []*Cookie
	for rows.Next() {
		var rowID, expiry, creationTime, sameSite int64
		var isSecure, isHTTPOnly bool
		var name, value, host, path string

		if err := rows.Scan(&rowID, &name, &value, &host, &path, &expiry, &creationTime,
			&isSecure, &isHTTPOnly, &sameSite); err != nil {
			return nil, err
		}

		cs = append(cs, &Cookie{
			C: cookies.C{
				Name:    name,
				Value:   value,
				Domain:  host,
				Path:    path,
				Expires: time.Unix(expiry, 0).UTC(),
				Created: time.UnixMicro(creationTime).UTC(),
				Flags: cookies.Flags{
					Secure:   isSecure,
					HTTPOnly: isHTTPOnly,
				},
				SameSite: decodeSitePolicy(sameSite),
			},
			id: rowID,
		})
	}
	return cs, nil
}

func (s *Store) dropCookie(tx *sql.Tx, c *Cookie) error {
	_, err := tx.Exec(`DELETE FROM moz_cookies WHERE id = ?`, c.id)
	return err
}

func (s *Store) writeCookie(tx *sql.Tx, c *Cookie) error {
	_, err := tx.Exec(`UPDATE moz_cookies SET `+
		`name = ?, value = ?, host = ?, path = ?, expiry = ?, creationTime = ?, `+
		`isSecure = ?, isHttpOnly = ?, sameSite = ? `+
		`WHERE id = ?`,
		c.Name, c.Value, c.Domain, c.Path, c.Expires.Unix(), c.Created.UnixMicro(),
		boolToInt(c.Flags.Secure), boolToInt(c.Flags.HTTPOnly), encodeSitePolicy(c.SameSite),
		c.id,
	)
	return err
}

func boolToInt(ok bool) int {
	if ok {
		return 1
	}
	return 0
}

func decodeSitePolicy(ss int64) cookies.SameSite {
	switch ss {
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

func encodeSitePolicy(ss cookies.SameSite) int {
	switch ss {
	case cookies.Lax:
		return 1
	case cookies.Strict:
		return 2
	default:
		return 0 // for Firefox this means "None"
	}
}
