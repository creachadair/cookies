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

// Package cookies reads and modifies browser cookies.
package cookies

import "time"

// C is a format-independent representation of a browser cookie.
type C struct {
	Name   string
	Value  string
	Domain string
	Path   string

	Expires  time.Time // if zero, has no expiration
	Created  time.Time
	Flags    Flags
	SameSite SameSite
}

// SameSite describes a first-party cookie policy.
type SameSite int

// Enumerators for SameSite policies.
const (
	Unknown SameSite = iota // unknown or unspecified policy
	Lax                     // top-level navigations and 3rd-party GET requests
	Strict                  // first-party context only
	None                    // unrestricted; send to all origins
)

var sameSiteStrings = [...]string{"Unknown", "Lax", "Strict", "None"}

func (s SameSite) String() string {
	if s < 0 || int(s) >= len(sameSiteStrings) {
		return sameSiteStrings[0]
	}
	return sameSiteStrings[s]
}

// Flags represents the optional flags that can be set on a cookie.
type Flags struct {
	Secure   bool // only send this cookie on an encrypted connection
	HTTPOnly bool // do not expose this cookie to scripts
}

// An Editor maps between format-specific representation of a cookie and the
// format-independent version.
type Editor interface {
	// Get returns a format-independent representation of the receiver.
	Get() C

	// Set updates the contents of the receiver to match c.
	// It reports an error if c cannot be represented in the format.
	Set(c C) error
}

// An Action specifies the disposition of a cookie processed by the callback to
// the Scan method of a Store.
type Action int

// Values for the Action enumeration.
const (
	Keep    Action = 1 + iota // keep the cookie in the store, unmodified
	Update                    // keep the cookie in the store, with modifications
	Discard                   // discard the cookie from the store
)

var actionStrings = [...]string{"Invalid", "Keep", "Update", "Discard"}

func (a Action) String() string {
	if a < 0 || int(a) >= len(actionStrings) {
		return actionStrings[0]
	}
	return actionStrings[a]
}

// A ScanFunc is a callback to scan each cookie in a store.
type ScanFunc func(Editor) (Action, error)

// Store is the interface for a collection of cookies.
type Store interface {
	// Scan calls f for each cookie in the store.
	//
	// If f reports an error, scanning stops and that error is returned to the
	// caller of Scan. Otherwise, the cookie is handled according to the Action
	// reported by f.
	//
	// if f returns Discard, the cookie is removed from the store.
	//
	// If f returns Update, the cookie is updated with any modifications made by
	// f via the Editor interface.
	//
	// If f returns Keep, the cookie is retained as-presented, and any
	// modifications made by f are discarded.
	//
	// If f returns an unknown Action value, Scan must report an error.
	Scan(f ScanFunc) error

	// Commit commits any pending modifications to persistent storage.
	Commit() error
}
