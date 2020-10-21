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

package bincookie

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/creachadair/atomicfile"
	"github.com/creachadair/cookies"
)

// Open opens a bincookie file and returns a Store containing its data.
func Open(path string) (*Store, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := ParseFile(data)
	if err != nil {
		return nil, err
	}
	return &Store{
		path: path,
		file: f,
	}, nil
}

// A Store represents a collection of bincookies stored in a file.  A *Store
// satisfies the cookies.Store interface.
type Store struct {
	path  string
	file  *File
	dirty bool
}

// WriteTo encodes the file associated with s in binary format to w.
func (s *Store) WriteTo(w io.Writer) (int64, error) {
	return s.file.WriteTo(w)
}

// Scan implements part of the cookies.Store interface.
func (s *Store) Scan(f cookies.ScanFunc) error {
	for _, page := range s.file.Pages {
		var out []*Cookie
		for _, c := range page.Cookies {
			// Make a temporary copy of the cookie so that edits can be discarded
			// if the action is Keep.
			tmp := *c
			act, err := f(&tmp)
			if err != nil {
				return err
			}
			switch act {
			case cookies.Keep:
				out = append(out, c) // discard changes
			case cookies.Update:
				out = append(out, &tmp) // include updates
				s.dirty = true
			case cookies.Discard:
				s.dirty = true // discard entirely
			default:
				return fmt.Errorf("unknown action: %v", act)
			}
		}
		page.Cookies = out
	}
	return nil
}

// Commit implements part of the cookies.Store interface.
func (s *Store) Commit() error {
	if s.dirty {
		f, err := atomicfile.New(s.path, 0600)
		if err != nil {
			return err
		}
		defer f.Cancel()
		if _, err := s.file.WriteTo(f); err != nil {
			return err
		}
		return f.Close()
	}
	return nil
}
