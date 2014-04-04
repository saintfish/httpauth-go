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
	cookieXsrfAuth *Cookie
)

func init() {
	cookieXsrfAuth = NewCookie("golang", "/cookie/login/", func(username, password string) bool {
		return username == password
	})
	cookieXsrfAuth.RequireXsrfHeader = true
}

func cookieXsrfHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/cookie/":
		username := cookieXsrfAuth.Authorize(r)
		if username == "" {
			cookieXsrfAuth.NotifyAuthRequired(w, r)
			return
		}

		fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
	case "/cookie/login/":
		fmt.Fprintf(w, htmlLogin)
	default:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
	}
}

func TestCookieXsrfNoAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(cookieXsrfHandler))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/cookie/")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != ts.URL+"/cookie/login/" {
		t.Errorf("Received incorrect page: %s", resp.Request.URL.String())
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != htmlLogin {
		t.Errorf("Incorrect body text.")
	}

}

func TestCookieXsrfMissingHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(cookieXsrfHandler))
	defer ts.Close()

	nonce, err := cookieXsrfAuth.createSession("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	req, err := http.NewRequest("GET", ts.URL+"/cookie/", nil)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: nonce})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != ts.URL+"/cookie/login/" {
		t.Errorf("Received incorrect page: %s", resp.Request.URL.String())
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != htmlLogin {
		t.Errorf("Incorrect body text.")
	}
}

func TestCookieXsrfGoodAuth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(cookieXsrfHandler))
	defer ts.Close()

	nonce, err := cookieXsrfAuth.createSession("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	req, err := http.NewRequest("GET", ts.URL+"/cookie/", nil)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: nonce})
	req.Header.Add("X-XSRF-Cookie", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != ts.URL+"/cookie/" {
		t.Errorf("Received incorrect page: %s", resp.Request.URL.String())
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != "<html><body><h1>Hello</h1><p>Welcome, user1</p></body></html>" {
		t.Errorf("Incorrect body text.")
	}

}

func TestCookieXsrfLogoutWeb(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(cookieXsrfHandler))
	defer ts.Close()

	nonce, err := cookieXsrfAuth.createSession("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	req, err := http.NewRequest("GET", ts.URL+"/cookie/", nil)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: nonce})
	req.Header.Add("X-XSRF-Cookie", "true")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != ts.URL+"/cookie/" {
		t.Errorf("Received incorrect page: %s", resp.Request.URL.String())
	}

	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if string(buffer) != "<html><body><h1>Hello</h1><p>Welcome, user1</p></body></html>" {
		t.Errorf("Incorrect body text.")
	}

}
