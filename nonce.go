// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"crypto/rand"
	"encoding/base64"
)

const (
	// The length of a nonce
	nonceLen = 16
)

func createNonce() (string, error) {
	var buffer [12]byte

	for i := 0; i < len(buffer); {
		n, err := rand.Read(buffer[i:])
		if err != nil {
			return "", err
		}
		i += n
	}
	return base64.StdEncoding.EncodeToString(buffer[0:]), nil
}
