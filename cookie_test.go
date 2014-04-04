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
	cookieAuth *Cookie
)

const (
	htmlLogin string = `<html><head><title>Login</title></head><body><p>There should be a login form here</p></body></html>`
)

func init() {
	cookieAuth = NewCookie("golang", "/cookie/login/", func(username, password string) bool {
		return username == password
	})
}

func cookieHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/cookie/":
		username := cookieAuth.Authorize(r)
		if username == "" {
			cookieAuth.NotifyAuthRequired(w, r)
			return
		}

		fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
		
	case "/cookie/login/":
		fmt.Fprintf(w, htmlLogin)
		
	default:
		http.Error( w, "Not found.", http.StatusNotFound )
	}
}


func TestCookieNoAuth(t *testing.T) {
	ts := httptest.NewServer( http.HandlerFunc(cookieHandler))
	defer ts.Close()
	
	resp, err := http.Get(ts.URL + "/cookie/" )
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != ts.URL +"/cookie/login/" {
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

func TestCookieCreateSession(t *testing.T) {
	nonce1, err := cookieAuth.createSession("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	nonce2, err := cookieAuth.createSession("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if nonce1 != nonce2 {
		t.Errorf("Error when login twice using the same username.")
	}
}

func TestCookieDestroySession(t *testing.T) {
	nonce, err := cookieAuth.createSession("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	cookieAuth.destroySession(nonce)
}

func TestCookieGoodAuth(t *testing.T) {
	ts := httptest.NewServer( http.HandlerFunc(cookieHandler))
	defer ts.Close()
	
	nonce, err := cookieAuth.createSession("user1", "user1")
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

func TestCookieLogout(t *testing.T) {
	ts := httptest.NewServer( http.HandlerFunc(cookieHandler))
	defer ts.Close()
	
	nonce, err := cookieAuth.createSession("user1", "user1")
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
