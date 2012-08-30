// Copyright 2012 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"container/heap"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// The default value for ClientCacheResidence used when creating new Digest instances.
	DefaultClientCacheResidence = 1 * time.Hour
)

type digestClientInfo struct {
	numContacts uint64 // number of client connects
	lastContact int64  // time of last communication with this client (unix nanoseconds)
	nonce       string // unique per client salt
}

type digestPriorityQueue []*digestClientInfo

func (pq digestPriorityQueue) Len() int {
	return len(pq)
}

func (pq digestPriorityQueue) Less(i, j int) bool {
	return pq[i].lastContact < pq[j].lastContact
}

func (pq digestPriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *digestPriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*digestClientInfo))
}

func (pq *digestPriorityQueue) Pop() interface{} {
	n := len(*pq)
	ret := (*pq)[n-1]
	*pq = (*pq)[:n-1]
	return ret
}

func (pq digestPriorityQueue) MinValue() int64 {
	n := len(pq)
	return pq[n-1].lastContact
}

// A Digest is a policy for authenticating users using the digest authentication scheme.
type Digest struct {
	// Realm provides a 'namespace' where the authentication will be considered.
	Realm string
	// Auth provides a function or closure that retrieve the password for a given username.
	Auth PasswordLookup
	// This is a nonce used by the HTTP server to prevent dictionary attacks
	opaque string

	// CientCacheResidence controls how long client information is retained
	ClientCacheResidence time.Duration

	clients map[string]*digestClientInfo
	lru     digestPriorityQueue
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
		DefaultClientCacheResidence,
		make(map[string]*digestClientInfo),
		nil,
		md5.New()}, nil
}

func (a *Digest) evictLeastRecentlySeen() {
	now := time.Now().UnixNano()

	// Remove all entries from the client cache older than the
	// residence time.
	for len(a.lru) > 0 && a.lru.MinValue()+a.ClientCacheResidence.Nanoseconds() <= now {
		client := heap.Pop(&a.lru).(*digestClientInfo)
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
	// Check for old clientInfo, and evict those older than
	// residence time.
	a.evictLeastRecentlySeen()

	// Create an entry for the client
	nonce, err := createNonce()
	if err != nil {
		http.Error(w, "Internal server error.", http.StatusInternalServerError)
		return
	}
	ci := &digestClientInfo{0, time.Now().UnixNano(), nonce}
	a.clients[nonce] = ci
	heap.Push(&a.lru, ci)

	// Create the header
	hdr := `Digest realm="` + a.Realm + `", nonce="` + nonce + `", opaque="` +
		a.opaque + `", algorithm="MD5", qop="auth"`
	w.Header().Set("WWW-Authenticate", hdr)
	w.WriteHeader(http.StatusUnauthorized)
}
