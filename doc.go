// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package httpauth provides utilities to support HTTP authentication policies.
//
// The HTTP standard provides two different schemes for authorizing clients: the
// basic authorization scheme and the digest authorization scheme.  Both schemes
// are supported by the package, and the supporting types implement a common policy
// interface so that HTTP servers can easily change their authentication policy.
//
// To support the basic authentication scheme, callers will need to provide a
// function or closure that can validate a user's credentials (i.e. a username
// and password pair).  Alternatively, callers can provide a function that will
// retrieve the password for a given username.
//
// To support the digest authentication scheme, callers will need to provide a
// function or cluse that can retrieve the password for a given username.  The
// alternate approach (validating a set of credentials) is not supported.
//
// Additionally, this package supports the cookie authentication scheme.
// The caller must provide a URL with a login form or some other method
// to obtain the user's credentials.  After these credentials have been
// verified, a cookie is set on the clients computer containing a token.
// The presence (and validity) of this token serves to authorize future
// HTTP requests.
package httpauth
