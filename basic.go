// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// A Basic is a policy for authenticating users using the basic authentication scheme.
type Basic struct {
	// Realm provides a 'namespace' where the authentication will be considered.
	Realm string
	// Auth provides a function or closure that can validate if a username/password combination is valid
	Auth Authenticator
}

// NewBasic creates a new authentication policy that uses the basic authentication scheme.
func NewBasic(realm string, auth Authenticator) *Basic {
	return &Basic{realm, auth}
}

// Authorize retrieves the credientials from the HTTP request, and 
// returns the username only if the credientials could be validated.
// If the return value is blank, then the credentials are missing,
// invalid, or a system error prevented verification.
func (a *Basic) Authorize(r *http.Request) (username string) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return ""
	}

	// Check that the token supplied corresponds to the basic authorization
	// protocol
	ndx := strings.IndexRune(token, ' ')
	if ndx < 1 || token[0:ndx] != "Basic" {
		return ""
	}

	// Drop prefix, and decode the base64
	buffer, err := base64.StdEncoding.DecodeString(token[ndx+1:])
	if err != nil {
		return ""
	}
	token = string(buffer)

	ndx = strings.IndexRune(token, ':')
	if ndx < 1 {
		return ""
	}

	if !a.Auth(token[0:ndx], token[ndx+1:]) {
		return ""
	}

	return token[0:ndx]
}

// NotifyAuthRequired adds the headers to the HTTP response to 
// inform the client of the failed authorization, and which scheme
// must be used to gain authentication.
func (a *Basic) NotifyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\""+a.Realm+"\"")
	w.WriteHeader(http.StatusUnauthorized)
}

// ParseToken is a helper function that extracts the username and password
// from an authorization token.  Callers should be able to pass in the header
// "Authorization" from an HTTP request, and retrieve the credentials.
func (a *Basic) ParseToken(token string) (username, password string) {
	if token == "" {
		return "", ""
	}

	// Check that the token supplied corresponds to the basic authorization
	// protocol
	ndx := strings.IndexRune(token, ' ')
	if ndx < 1 || token[0:ndx] != "Basic" {
		return "", ""
	}

	// Drop prefix, and decode the base64
	buffer, err := base64.StdEncoding.DecodeString(token[ndx+1:])
	if err != nil {
		return "", ""
	}
	token = string(buffer)

	ndx = strings.IndexRune(token, ':')
	if ndx < 1 {
		return "", ""
	}

	return token[0:ndx], token[ndx+1:]
}
