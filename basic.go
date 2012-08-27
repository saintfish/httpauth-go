package httpauth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

type Authenticator func (username, password string) bool

type Basic struct {
	Realm string
	Auth Authenticator
}

func NewBasic( realm string, auth Authenticator ) *Basic {
	return &Basic{ realm, auth }
}

func (a *Basic) Authorize(r *http.Request) (username string) {
	token := r.Header.Get("Authorization")
	if token=="" {
		return ""
	}

	// Check that the token supplied corresponds to the basic authorization
	// protocol
	ndx := strings.IndexRune( token, ' ' )
	if ndx<1 || token[0:ndx]!="Basic" {
		return ""
	}

	// Drop prefix, and decode the base64
	buffer, err := base64.StdEncoding.DecodeString(token[ndx+1:])
	if err!= nil {
		return ""
	}
	token = string(buffer)

	ndx = strings.IndexRune( token, ':' )
	if ndx<1 {
		return ""
	}

	if !a.Auth( token[0:ndx], token[ndx+1:] ) {
		return ""
	}

	return token[0:ndx]
}

func (a *Basic) NotifyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"" + a.Realm + "\"" )
	w.WriteHeader(http.StatusUnauthorized)
}

