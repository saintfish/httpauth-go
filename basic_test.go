package httpauth

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
)

var (
	auth *Basic
)

const (
	port    string = ":8080"
	html401 string = "<html><body><h1>Unauthorized</h1></body></html>"
)

func init() {
	auth = NewBasic("golang", func(username, password string) bool {
		return username == password
	})

	http.HandleFunc("/", handler)
	go http.ListenAndServe(port, nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
	username := auth.Authorize(r)
	if username == "" {
		auth.NotifyAuthRequired(w)
		fmt.Fprintf(w, html401)
		return
	}

	fmt.Fprintf(w, "<html><body><h1>Hello</h1><p>Welcome, %s</p></body></html>", username)
}

func TestNoAuth(t *testing.T) {
	resp, err := http.Get("http://localhost" + port)
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

	if string(buffer) != html401 {
		println(string(buffer))
		t.Errorf("Incorrect body text.")
	}

}

func TestBadAuth(t *testing.T) {
	resp, err := http.Get("http://user:pass@localhost" + port)
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

	if string(buffer) != html401 {
		println(string(buffer))
		t.Errorf("Incorrect body text.")
	}

}

func TestGoodAuth(t *testing.T) {
	resp, err := http.Get("http://user:user@localhost" + port)
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

	if string(buffer) != "<html><body><h1>Hello</h1><p>Welcome, user</p></body></html>" {
		println(string(buffer))
		t.Errorf("Incorrect body text.")
	}

}

func TestCredientials(t *testing.T) {
	resp, err := http.Get("http://user:pass@localhost" + port)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	token := resp.Request.Header.Get("Authorization")
	username, password := auth.ParseToken(token)
	if username != "user" || password != "pass" {
		t.Errorf("auth.Credentials returned incorrect values.")
	}
}
