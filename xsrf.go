// Copyright 2014 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"net/http"
)

// VerifyXsrfHeader returns whether or not the HTTP request contains a
// header with the name X-Xsrf-Cookie.  The exact value of the header is
// not verified, the header must simply exist.  This should prove that the
// request was initiated using XMLHttpRequest, and therefore not by a
// normal HTTP client.
func VerifyXsrfHeader(req *http.Request) bool {
	_, ok := req.Header["X-Xsrf-Cookie"]
	return ok
}
