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

package chromedb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"errors"

	"golang.org/x/crypto/pbkdf2"
)

const (
	versionTag = "v10"
	keyBytes   = 16
	keySalt    = "saltysalt"
	ivString   = "                "
)

// encryptionKey generates an encryption key from the given passphrase, using
// the specified number of PBKDF2 iterations.
func encryptionKey(passphrase string, iterations int) []byte {
	return pbkdf2.Key([]byte(passphrase), []byte(keySalt), iterations, keyBytes, sha1.New)
}

// encryptValue encrypts a cookie value with the given key.
// Encryption is AES in CBC mode, using a key derived from a user passphrase
// with PBKDF2.
func encryptValue(key, val []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Pack the value for encryption. The value must be padded to a positive
	// multiple of 16 bytes. The padding consists of n bytes of value n.
	// The padded value is prefixed with the version tag "v10".
	//
	//   | clear | encrypted            |
	//   +-------+-----...--+-----...---+
	//   | v 1 0 | val ...  | p p ... p |
	//   +-------+-----...--+-----...---+
	//
	padBytes := padLength(len(val))
	buf := make([]byte, len(versionTag)+len(val)+padBytes)
	copy(buf, []byte(versionTag))
	copy(buf[3:], val)
	for i := 3 + len(val); i < len(buf); i++ {
		buf[i] = byte(padBytes)
	}

	enc := cipher.NewCBCEncrypter(c, []byte(ivString))
	enc.CryptBlocks(buf[3:], buf[3:])
	return buf, nil
}

// decryptValue decrypts a cookie value with the given key.
func decryptValue(key, val []byte) ([]byte, error) {
	if !bytes.HasPrefix(val, []byte(versionTag)) {
		return nil, errors.New("invalid encryped value prefix")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dec := cipher.NewCBCDecrypter(c, []byte(ivString))
	dec.CryptBlocks(val[3:], val[3:])
	return checkValue(val[3:])
}

func padLength(n int) int {
	if n%16 == 0 {
		return 16 // ensure there is alwyas at least 1 byte of padding
	}
	return 16 - (n % 16)
}

// checkValue removes the padding from a decrypted value and verifies that it
// has the correct form. If not, the decryption key is assumed to be wrong and
// an error is reported.
func checkValue(val []byte) ([]byte, error) {
	np := int(val[len(val)-1])
	if np < 1 || np > 16 || np > len(val) {
		return nil, errors.New("invalid decryption key")
	}
	for i := len(val) - np; i < len(val); i++ {
		if int(val[i]) != np {
			return nil, errors.New("invalid decryption key")
		}
	}
	return val[:len(val)-np], nil
}
