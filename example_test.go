// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"fmt"
	"net/http"
	"time"
)

func ExampleNewBasic() {
	const port = ":8080"

	// Create an authorization policy that uses the basic authorization
	// scheme.  The credientials will be considered valid if the password
	// is simply the username repeated twice.
	auth := NewBasic("My Website", func(username, password string) bool {
		return password == username+username
	}, nil)
	// The request handler
	http.HandleFunc("/example/", func(w http.ResponseWriter, r *http.Request) {
		// Check if the client is authorized
		username := auth.Authorize(r)
		if username == "" {
			// Oops!  Access denied.
			auth.NotifyAuthRequired(w, r)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
	})

	// This is just an example.  Run the HTTP server for a second and then quit.
	go http.ListenAndServe(port, nil)
	time.Sleep(1 * time.Second)
}

func ExamplePasswordLookup_Authenticator() {
	// Create a dummy PasswordLookup for this example.
	pl := PasswordLookup(func(username string) string {
		// A user's password is their username with the digit '9' added
		return username + "9"
	})

	// To use the basic authentication scheme, we need an Authenicator
	auth := pl.Authenticator()

	// Create a authentication scheme
	_ /*policy*/ = NewBasic("My Website", auth, nil)
}

func ExampleNewCookie() {
	const port = ":8080"

	// Create an authorization policy that uses the cookie authorization
	// scheme.  The credientials will be considered valid if the password
	// is simply the username repeated twice.
	auth := NewCookie("My Website", "/login", func(username, password string) bool {
		return password == username+username
	})
	// The request handler
	http.HandleFunc("/example/", func(w http.ResponseWriter, r *http.Request) {
		// Check if the client is authorized
		username := auth.Authorize(r)
		if username == "" {
			// Oops!  Access denied.
			// This will redirect the HTTP client to the path /login.
			auth.NotifyAuthRequired(w, r)
			return
		}
		fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
	})
	http.HandleFunc("/login/", func(w http.ResponseWriter, r *http.Request) {
		// Get the username and password from the request.  This will
		// depend on the callee, but could be as simple as calling
		// ParseFrom on the request.
		username := /* implementation specific */ "user1"
		password := /* implementation specific */ "password1"

		err := auth.Login(w, username, password)
		if err == ErrBadUsernameOrPassword {
			http.Error(w, "Someone is misbehaving.", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "Internal server error.", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/example", http.StatusTemporaryRedirect)
	})

	// This is just an example.  Run the HTTP server for a second and then quit.
	go http.ListenAndServe(port, nil)
	time.Sleep(1 * time.Second)
}
