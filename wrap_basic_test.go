// Copyright 2013 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func wrappedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, authenticated user!</p></body></html>")
}

func TestWrapBasicNoAuth(t *testing.T) {
	ts := httptest.NewServer(NewHandlerWithAuth(basicAuth, http.HandlerFunc(wrappedHandler)))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != StatusUnauthorizedHtml {
		println(string(buffer))
		t.Errorf("Incorrect body text.")
	}

}

func TestWrapBasicBadAuth(t *testing.T) {
	ts := httptest.NewServer(NewHandlerWithAuth(basicAuth, http.HandlerFunc(wrappedHandler)))
	defer ts.Close()

	resp, err := http.Get("http://user:pass@" + ts.URL[7:])
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != StatusUnauthorizedHtml {
		println(string(buffer))
		t.Errorf("Incorrect body text.")
	}

}

func TestWrapBasicGoodAuth(t *testing.T) {
	ts := httptest.NewServer(NewHandlerWithAuth(basicAuth, http.HandlerFunc(wrappedHandler)))
	defer ts.Close()

	resp, err := http.Get("http://user:user@" + ts.URL[7:])
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != "<html><body><h1>Hello</h1><p>Welcome, authenticated user!</p></body></html>" {
		println(string(buffer))
		t.Errorf("Incorrect body text.")
	}

}

func TestWrapBasicCredientials(t *testing.T) {
	ts := httptest.NewServer(NewHandlerWithAuth(basicAuth, http.HandlerFunc(wrappedHandler)))
	defer ts.Close()

	resp, err := http.Get("http://user:pass@" + ts.URL[7:])
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	token := resp.Request.Header.Get("Authorization")
	username, password := basicAuth.ParseToken(token)
	if username != "user" || password != "pass" {
		t.Errorf("auth.Credentials returned incorrect values.")
	}
}
