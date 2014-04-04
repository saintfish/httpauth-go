// Copyright 2012 Robert W. Johnstone. All rights reserved.
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

var (
	// Verify that the policy provided by Basic meets the requirements
	// of the interface Policy
	_ Policy = &Digest{}

	// The following policy is used for all of the tests in this file
	digestAuth *Digest
	success    chan bool
)

func init() {
	var err error
	digestAuth, err = NewDigest("golang", func(username string) string {
		return username
	}, nil)
	if err != nil {
		panic(err)
	}

	success = make(chan bool)
}

func digestHandler(w http.ResponseWriter, r *http.Request) {
	username := digestAuth.Authorize(r)
	if username == "" {
		digestAuth.NotifyAuthRequired(w, r)
		return
	}

	// Ignore spurious requests
	if r.URL.String()[0:7] != "/digest" {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	fmt.Println("digest", r.URL)
	fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
	success <- true
}

func TestDigestNoAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(digestHandler))
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

func TestDigestBadAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(digestHandler))
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

func TestDigestBrowser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test of digest authorization.")
	}

	ts := httptest.NewServer(http.HandlerFunc(digestHandler))
	defer ts.Close()

	url := "http://user:user@" + ts.URL[7:] + "/digest/"
	fmt.Println("Use a webbrowser, and navigate to", url, "to check digest authentication.")
	fmt.Println("For authentication to succeed, the username and password must match.")
	<-success
}

func TestDigestBrowser2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test of digest authorization.")
	}

	ts := httptest.NewServer(http.HandlerFunc(digestHandler))
	defer ts.Close()

	url := "http://user:user@" + ts.URL[7:] + "/digest/"
	fmt.Println("Use a webbrowser, and navigate to", url, "to check digest authentication.")
	fmt.Println("For authentication to succeed, the username and password must match.")
	<-success
	url = url + "sub/"
	fmt.Println("Now try", url, "to check digest authentication.")
	<-success
}
