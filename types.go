package httpauth

import (
	"net/http"
)

// An Authenticator is a caller supplied closure that can check the authorization
// of username/password pairs.  The function should return true only if the 
// credentials can be successfully validated.
type Authenticator func(username, password string) bool

// A Policy is a type that implements a HTTP authentication scheme.  Two 
// standard schemes are the basic authentication scheme and the digest 
// access authentication scheme.
type Policy interface {
	// Authorize retrieves the credientials from the HTTP request, and 
	// returns the username only if the credientials could be validated.
	// If the return value is blank, then the credentials are missing,
	// invalid, or a system error prevented verification.
	Authorize(r *http.Request) (username string)
	// NotifyAuthRequired adds the headers to the HTTP response to 
	// inform the client of the failed authorization, and which scheme
	// must be used to gain authentication.
	NotifyAuthRequired(w http.ResponseWriter)
}
