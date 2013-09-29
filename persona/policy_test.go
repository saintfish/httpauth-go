// Copyright 2013 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	httpauth "bitbucket.org/rj/httpauth-go"
	"net/http"
	"testing"
	"time"
)

var (
	auth = NewPolicy( "test", "/index.html" )
	poicy httpauth.Policy = auth
	good bool
)

func init() {
	http.HandleFunc( "/auth/login", func (w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		if err!=nil {
			http.Error( w, http.StatusText(http.StatusBadRequest) + "\n" + err.Error(), http.StatusBadRequest )
			return
		}
		err = auth.LoginWithResponse( w, r.Form["assertion"][0], r.Host )
		if err!=nil {
			http.Error( w, http.StatusText(http.StatusUnauthorized) + "\n" + err.Error(), http.StatusUnauthorized )
			return
		}
		http.Error( w, http.StatusText(http.StatusOK), http.StatusOK )
	} )

	http.HandleFunc( "/index.html", func( w http.ResponseWriter, r *http.Request) {
		w.Write( []byte(
		`<html>
        <head>
			<title>A page</title>
<script src="//ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js"></script>
		</head>
        <body>
			<h1>Page</h1>
			<p><a id="signin" href="javascript:mylogin();">Log in</a></p>
			</form>
			<script src="https://login.persona.org/include.js"></script>
			<script>
function mylogin() {
	alert( 'Login');
	navigator.id.request();
}

currentUser = null

navigator.id.watch({
  loggedInUser: currentUser,
  onlogin: function(assertion) {
    // A user has logged in! Here you need to:
    // 1. Send the assertion to your backend for verification and to create a session.
    // 2. Update your UI.
    $.ajax({ /* <-- This example uses jQuery, but you can use whatever you'd like */
      type: 'POST',
      url: '/auth/login', // This is a URL on your website.
      data: {assertion: assertion},
      success: function(res, status, xhr) { alert("Login success: " + status ); /*window.location.reload();*/ },
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
      url: '/auth/logout', // This is a URL on your website.
      success: function(res, status, xhr) { window.location.reload(); },
      error: function(xhr, status, err) { alert("Logout failure: " + err); }
    });
  }
});			</script>
		</body>
		</html>` ))
	} )

	http.HandleFunc( "/data.html", func( w http.ResponseWriter, r *http.Request) {
		username := auth.Authorize(r)
		if username=="" {
			auth.NotifyAuthRequired(w,r)
			return
		}
		w.Write( []byte("SECRETE DATA") )
		good = true
	} )

	http.HandleFunc( "/", func( w http.ResponseWriter, r *http.Request) {
		http.Error( w, http.StatusText(http.StatusNotFound), http.StatusNotFound )
	} )
}
		

func TestVerify(t *testing.T) {
	err := http.ListenAndServe( ":8181", nil )
	if err!=nil {
		println( err.Error() )
		return
	}
	for !good {
		time.Sleep( 1 * time.Second )
	}
}
	
