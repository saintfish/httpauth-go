// Copyright 2013 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"
)

var (
	personaAuth    *Policy
	assertion      string
	assertion_ok   bool
	assertion_chan = make(chan string)
)

const (
	port      string = ":8181"
	htmlLogin string = `<html>
        <head>
			<title>A page</title>
			<script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
		</head>
        <body>
			<h1>Page</h1>
			<p><a id="signin" href="javascript:mylogin();">Log in</a></p>
			<script src="https://login.persona.org/include.js"></script>
			<script>
function mylogin() {
	alert( 'Login');
	navigator.id.request();
 }
 
currentUser = null;

navigator.id.watch({
  loggedInUser: currentUser,
  onlogin: function(assertion) {
    // A user has logged in! Here you need to:
    // 1. Send the assertion to your backend for verification and to create a session.
    // 2. Update your UI.
    $.ajax({ /* <-- This example uses jQuery, but you can use whatever you'd like */
      type: 'POST',
      url: '/persona/login2/', // This is a URL on your website.
      data: {assertion: assertion},
      success: function(res, status, xhr) { alert("Login success: " + status ); },
      error: function(xhr, status, err) {
        navigator.id.logout();
        alert("Login failure: " + err);
      }
    });
  },
  onlogout: function() {
    // A user has logged out! Here you need to:
    // Tear down the user's session by redirecting the user or making a call to your backend.
    // Also, make sure loggedInUser will get set to null on the next page load.
    // (That's a literal JavaScript null. Not false, 0, or undefined. null.)
    $.ajax({
      type: 'POST',
      url: '/persona/login2/', // This is a URL on your website.
      success: function(res, status, xhr) { window.location.reload(); },
      error: function(xhr, status, err) { alert("Logout failure: " + err); }
    });
  }

});			
</script>
		</body>
		</html>`
)

func init() {
	personaAuth = NewPolicy("golang", "/persona/login/")

	http.HandleFunc("/persona/login/", personaLoginHandler)
	http.HandleFunc("/persona/login2/", personaLogin2Handler)
	http.HandleFunc("/persona/", personaHandler)
	go http.ListenAndServe(port, nil)
	time.Sleep(2 * time.Second)
}

func personaHandler(w http.ResponseWriter, r *http.Request) {
	username := personaAuth.Authorize(r)
	if username == "" {
		personaAuth.NotifyAuthRequired(w, r)
		return
	}

	fmt.Fprintf(w, `<html><body><h1>Header</h1><p>Some text</p></body></html>`)
}

func personaLoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, htmlLogin)
}

func personaLogin2Handler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest)+"\n"+err.Error(), http.StatusBadRequest)
		return
	}
	user, err := Verify(r.Form["assertion"][0], r.Host)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	err = personaAuth.Login(w, user)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError)+"\n"+err.Error(), http.StatusInternalServerError)
		return
	}
	assertion_chan <- r.Form["assertion"][0]
	http.Error(w, http.StatusText(http.StatusOK), http.StatusOK)
}

func TestPolicyNoAuth(t *testing.T) {
	resp, err := http.Get("http://localhost" + port + "/persona/")
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Received incorrect status: %d", resp.StatusCode)
	}
	if resp.Request.URL.String() != "http://localhost"+port+"/persona/login/" {
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

func TestPauseForCredentials(t *testing.T) {
	fmt.Println("Waiting for assertion.  Please use web browser.")
	fmt.Println("http://localhost" + port + "/persona/login/")
	assertion = <-assertion_chan
	fmt.Println("Assertion received.")
}

func TestPersonaLogin(t *testing.T) {
	user, err := Verify(assertion, "localhost"+port)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	if user == nil {
		t.Fatalf("Call to Verify return nil user.")
	}

	nonce1, err := personaAuth.createSession(user)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if _, ok := personaAuth.clientsByNonce[nonce1]; !ok {
		t.Fatalf("Could not find nonce in the map of sessions.")
	}

	nonce2, err := personaAuth.createSession(user)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	if nonce1 != nonce2 {
		t.Errorf("Error when login twice using the same username.")
	}
}

func TestPersonaLogout(t *testing.T) {
	user, err := Verify(assertion, "localhost"+port)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}
	if user == nil {
		t.Fatalf("Call to Verify return nil user.")
	}

	nonce, err := personaAuth.createSession(user)
	if err != nil {
		t.Fatalf("Error:  %s", err)
	}

	personaAuth.destroySession(nonce)
	if _, ok := personaAuth.clientsByNonce[nonce]; ok {
		t.Fatalf("destroySession failed to remove client for the nonce.")
	}
}
