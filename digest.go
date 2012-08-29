// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// The default value for ClientCacheSize used when create new Digest instances.
	DefaultClientCacheSize = int(512)
	// The default value for ClientCacheDelta used when create new Digest instances.
	DefaultClientCacheDelta = int(32)
)

type clientInfo struct {
	numContacts uint64 // number of client connects
	lastContact int64  // time of last communication with this client
	nonce       string // unique per client salt
}

type clientInfoSlice []*clientInfo

func (c clientInfoSlice) Len() int {
	return len(c)
}

func (c clientInfoSlice) Less(i, j int) bool {
	return c[i].lastContact < c[j].lastContact
}

func (c clientInfoSlice) Swap(i, j int) {
	c[i], c[j] = c[j], c[i]
}

// A Digest is a policy for authenticating users using the digest authentication scheme.
type Digest struct {
	// Realm provides a 'namespace' where the authentication will be considered.
	Realm string
	// Auth provides a function or closure that retrieve the password for a given username.
	Auth PasswordLookup
	// This is a nonce used by the HTTP server to prevent dictionary attacks
	opaque string

	// ClientCacheSize controls how large the client cache can grow.
	ClientCacheSize int
	// ClientCacheDelta controls how frequently the client cache is trimmed.
	ClientCacheDelta int

	clients map[string]*clientInfo
	md5     hash.Hash
}

func createNonce() (string, error) {
	var buffer [12]byte

	for i := 0; i < len(buffer); {
		n, err := rand.Read(buffer[i:])
		if err != nil {
			return "", err
		}
		i += n
	}
	return base64.StdEncoding.EncodeToString(buffer[0:]), nil
}

func calcHash(h hash.Hash, data string) string {
	h.Reset()
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// NewDigest creates a new authentication policy that uses the digest authentication scheme.
func NewDigest(realm string, auth PasswordLookup) (*Digest, error) {
	nonce, err := createNonce()
	if err != nil {
		return nil, err
	}

	return &Digest{
		realm,
		auth,
		nonce,
		DefaultClientCacheSize,
		DefaultClientCacheDelta,
		make(map[string]*clientInfo),
		md5.New()}, nil
}

func (a *Digest) evictLeastRecentlySeen() {
	table := make([]*clientInfo, len(a.clients))
	i := 0
	for _, client := range a.clients {
		table[i] = client
		i++
	}

	sort.Sort(clientInfoSlice(table))

	for _, client := range table[:2*a.ClientCacheDelta] {
		delete(a.clients, client.nonce)
	}
}

// Authorize retrieves the credientials from the HTTP request, and 
// returns the username only if the credientials could be validated.
// If the return value is blank, then the credentials are missing,
// invalid, or a system error prevented verification.
func (a *Digest) Authorize(r *http.Request) (username string) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return ""
	}

	// Check that the token supplied corresponds to the digest authorization
	// protocol
	ndx := strings.IndexRune(token, ' ')
	if ndx < 1 || token[0:ndx] != "Digest" {
		return ""
	}
	token = token[ndx+1:]

	// Token is a comma separated list of name/value pairs
	params := make(map[string]string)
	for _, str := range strings.Split(token, ",") {
		ndx := strings.IndexRune(str, '=')
		if ndx < 1 {
			// malformed name/value pair
			// ignore
			continue
		}
		name := strings.Trim(str[0:ndx], `" `)
		value := strings.Trim(str[ndx+1:], `" `)
		params[name] = value
	}

	if params["opaque"] != a.opaque || params["algorithm"] != "MD5" || params["qop"] != "auth" {
		return ""
	}

	if params["uri"] != r.URL.Path {
		return ""
	}

	username = params["username"]
	if username == "" {
		return ""
	}
	password := a.Auth(username)
	if password == "" {
		return ""
	}
	ha1 := calcHash(a.md5, username+":"+a.Realm+":"+password)
	ha2 := calcHash(a.md5, r.Method+":"+r.URL.Path)
	ha3 := calcHash(a.md5, ha1+":"+params["nonce"]+":"+params["nc"]+
		":"+params["cnonce"]+":"+params["qop"]+":"+ha2)
	if ha3 != params["response"] {
		return ""
	}

	// Data is validated.  Find the client info.
	numContacts, err := strconv.ParseUint(params["nc"], 16, 64)
	if err != nil {
		return ""
	}
	if client, ok := a.clients[params["nonce"]]; ok {
		if client.numContacts != 0 && client.numContacts >= numContacts {
			return ""
		}
		client.numContacts = numContacts
		client.lastContact = time.Now().UnixNano()
	} else {
		return ""
	}

	return username
}

// NotifyAuthRequired adds the headers to the HTTP response to 
// inform the client of the failed authorization, and which scheme
// must be used to gain authentication.
func (a *Digest) NotifyAuthRequired(w http.ResponseWriter) {
	if len(a.clients) > a.ClientCacheSize+a.ClientCacheDelta {
		a.evictLeastRecentlySeen()
	}

	// Create an entry for the client
	nonce, err := createNonce()
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	a.clients[nonce] = &clientInfo{0, time.Now().UnixNano(), nonce}

	// Create the header
	hdr := `Digest realm="` + a.Realm + `", nonce="` + nonce + `", opaque="` +
		a.opaque + `", algorithm="MD5", qop="auth"`
	w.Header().Set("WWW-Authenticate", hdr)
	w.WriteHeader(http.StatusUnauthorized)
}
