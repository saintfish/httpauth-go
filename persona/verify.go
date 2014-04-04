// Copyright 2013 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

const (
	verifyUrl = "https://verifier.login.persona.org/verify"
)

// A User contains all of the information provided by Persona for an authenticated user.
type User struct {
	// Email is the username for the authenticated user.
	Email string
	// The website URL for which the user was authenticated.
	Audience string
	// The date and time when the authorization will expire on the Persona servers.
	Expires time.Time
	// The hostname of the identity provider that issued the assertion.
	Issuer string
}

type verifyResponse struct {
	Status string `json:"status"`

	Email    string `json:"email"`
	Audience string `json:"audience"`
	Expires  int64  `json:"expires"`
	Issuer   string `json:"issuer"`

	Reason string `json:"reason"`
}

// An error encapsulates the reason that the Persona identity provided could not verify an assertion.
type Error struct {
	Reason string
}

func (e Error) Error() string {
	return "Invalid assertion:  " + e.Reason
}

// Verify checks with the Persona server to validate an assertion.  If the assertion is valid,
// this routine will provide details about the user.
func Verify(assertion, audience string) (*User, error) {
	// Post to serice to authenticate the token
	postBody := strings.NewReader("assertion=" + assertion + "&audience=" + audience)
	res, err := http.Post(verifyUrl, "application/x-www-form-urlencoded", postBody)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// Read the result
	resBody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var ret verifyResponse
	err = json.Unmarshal(resBody, &ret)
	if err != nil {
		return nil, err
	}
	if ret.Status != "okay" {
		return nil, Error{ret.Reason}
	}

	return &User{ret.Email, ret.Audience, time.Unix(ret.Expires/1000, (ret.Expires%1000)*1000), ret.Issuer}, nil
}
