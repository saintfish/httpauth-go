// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

var (
	cookieXsrfAuth *Cookie
)

func init() {
	cookieXsrfAuth = NewCookie("golang", "http://localhost"+port+"/cookie_xsrf/login/", func(username, password string) bool {
		return username == password
	})
	cookieXsrfAuth.RequireXsrfHeader = true

	http.HandleFunc("/cookie_xsrf/login/", cookieXsrfLoginHandler)
	http.HandleFunc("/cookie_xsrf/", cookieXsrfHandler)
	go http.ListenAndServe(port, nil)
	time.Sleep(1 * time.Second)
}

func cookieXsrfHandler(w http.ResponseWriter, r *http.Request) {
	username := cookieXsrfAuth.Authorize(r)
	if username == "" {
		cookieXsrfAuth.NotifyAuthRequired(w, r)
		return
	}

	fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
}

func cookieXsrfLoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlLogin)
}

func TestCookieXsrfNoAuth(t *testing.T) {
	resp, err := http.Get("http://localhost" + port + "/cookie_xsrf/")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != "http://localhost"+port+"/cookie_xsrf/login/" {
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
	nonce, err := cookieXsrfAuth.Login("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	req, err := http.NewRequest("GET", "http://localhost"+port+"/cookie_xsrf/", nil)
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
	if resp.Request.URL.String() != "http://localhost"+port+"/cookie_xsrf/login/" {
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
	nonce, err := cookieXsrfAuth.Login("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	req, err := http.NewRequest("GET", "http://localhost"+port+"/cookie_xsrf/", nil)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: nonce})
	req.Header.Add( "X-XSRF-Cookie", "true" )

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != "http://localhost"+port+"/cookie_xsrf/" {
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
	nonce, err := cookieXsrfAuth.Login("user1", "user1")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	req, err := http.NewRequest("GET", "http://localhost"+port+"/cookie_xsrf/", nil)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	req.AddCookie(&http.Cookie{Name: "Authorization", Value: nonce})
	req.Header.Add( "X-XSRF-Cookie", "true" )

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != "http://localhost"+port+"/cookie_xsrf/" {
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
