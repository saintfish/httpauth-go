// Copyright 2013 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

import (
	"container/heap"
	"errors"
	"html"
	"net/http"
	"sync"
	"time"
)

const (
	// The default value for ClientCacheResidence used when creating new Digest instances.
	DefaultClientCacheResidence = 1 * time.Hour
	// The cookie name used to store authorization information
	cookieName = "Authorization"
)

var (
	ErrBadUsernameOrPassword = errors.New("Bad username or password.")
	ErrInvalidToken          = errors.New("The session token was invalid.")
)

type clientInfo struct {
	username    string // username for this authorized connection
	lastContact int64  // time of last communication with this client (unix nanoseconds)
	nonce       string // unique per client salt
}

type priorityQueue []*clientInfo

func (pq priorityQueue) Len() int {
	return len(pq)
}

func (pq priorityQueue) Less(i, j int) bool {
	return pq[i].lastContact < pq[j].lastContact
}

func (pq priorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *priorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*clientInfo))
}

func (pq *priorityQueue) Pop() interface{} {
	n := len(*pq)
	ret := (*pq)[n-1]
	*pq = (*pq)[:n-1]
	return ret
}

func (pq priorityQueue) MinValue() int64 {
	n := len(pq)
	return pq[n-1].lastContact
}

// A Policy is an authentication policy (in the sense of the httpauth package) for authenticating
// users.  The policy verifies that users credentials using Mozilla's Persona, and
// then setting a cookie stored on the client to verify authorized clients.  This
// authentication scheme is more involved than the others, as callers will need to implement URLs
// for login and logout pages.
type Policy struct {
	// Realm provides a 'namespace' where the authentication will be considered.
	Realm string
	// Clients are redirected to the LoginPage when they don't have authorization
	LoginPage string
	// Path sets the scope of the authorization cookie
	Path string

	// CientCacheResidence controls how long client information is retained
	ClientCacheResidence time.Duration

	mutex          sync.Mutex
	clientsByNonce map[string]*clientInfo
	clientsByUser  map[string]*clientInfo
	lru            priorityQueue
}

// NewPolicy creates a new authentication policy that uses Mozilla's Persona.
func NewPolicy(realm, url string) *Policy {
	return &Policy{
		realm,
		url,
		"/",
		DefaultClientCacheResidence,
		sync.Mutex{},
		make(map[string]*clientInfo),
		make(map[string]*clientInfo),
		nil}
}

func (a *Policy) evictLeastRecentlySeen() {
	now := time.Now().UnixNano()

	// Remove all entries from the client cache older than the
	// residence time.
	for len(a.lru) > 0 && a.lru.MinValue()+a.ClientCacheResidence.Nanoseconds() <= now {
		client := heap.Pop(&a.lru).(*clientInfo)
		delete(a.clientsByNonce, client.nonce)
		delete(a.clientsByUser, client.username)
	}
}

// Authorize retrieves the credientials from the HTTP request, and
// returns the username only if the credientials could be validated.
// If the return value is blank, then the credentials are missing,
// invalid, or a system error prevented verification.
func (a *Policy) Authorize(r *http.Request) (username string) {
	// Find the nonce used to identify a client
	token, err := r.Cookie(cookieName)
	if err != nil || token.Value == "" {
		return ""
	}
	if len(token.Value) != nonceLen {
		return ""
	}

	// Lock before mutating the fields of the policy
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Do we have a client with that nonce?
	if client, ok := a.clientsByNonce[token.Value]; ok {
		client.lastContact = time.Now().UnixNano()
		return client.username
	}
	return ""
}

// NotifyAuthRequired adds the headers to the HTTP response to
// inform the client of the failed authorization, and which scheme
// must be used to gain authentication.
//
// Caller's should consider adding sending an HTML response with a link
// to the login page for GET requests.
func (a *Policy) NotifyAuthRequired(w http.ResponseWriter, r *http.Request) {
	// This code is derived from http.Redirect
	w.Header().Set("Location", a.LoginPage)
	w.WriteHeader(http.StatusTemporaryRedirect)

	// RFC2616 recommends that a short note "SHOULD" be included in the
	// response because older user agents may not understand 301/307.
	// Shouldn't send the response for POST or HEAD; that leaves GET.
	if r.Method == "GET" {
		note := "<a href=\"" + html.EscapeString(a.LoginPage) + "\">" + http.StatusText(http.StatusTemporaryRedirect) + "</a>.\n"
		w.Write([]byte(note))
	}

	// Lock before mutating the fields of the policy
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Check for old clientInfo, and evict those older than
	// residence time.
	a.evictLeastRecentlySeen()
}

// The function createSession creates a client entry.  The nonce can be
// used by the client to identify the session.
//
// This functions handles internal details of creating the session only.
// The caller is still responsible for creating the HTTP response, which
// will need to save the returned nonce.
//
// The credentials are assumed to be verified.  They are not validated
// before creating the session.
func (a *Policy) createSession(user *User) (nonce string, err error) {
	// Create an entry for this user
	nonce, err = createNonce()
	if err != nil {
		return "", err
	}

	// Lock before mutating the fields of the policy
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Check if there is already a session for this username
	if ci, ok := a.clientsByUser[user.Email]; ok {
		ci.lastContact = time.Now().UnixNano()
		return ci.nonce, nil
	}

	ci := &clientInfo{user.Email, time.Now().UnixNano(), nonce}
	a.clientsByNonce[nonce] = ci
	a.clientsByUser[user.Email] = ci

	return nonce, nil
}

// Login creates a session for the user, and then a cookie is set on the
// HTTP response so that the client can access the session in future
// HTTP requests.
//
// The argument should be obtained by a call to Verify, which will verify
// the user's credentials.
//
// The caller is responsable for create an appropriate response body for
// the HTTP request. For successful validation, redirection (http.StatusTemporaryRedirect)
// to the protected content is most likely the correct response.
//
// If the credentials cannot be verified, an error (ErrBadUsernameOrPassword) is
// returned.  The caller is then responsable for creating an appropriate reponse to
// the HTTP request.
func (a *Policy) Login(w http.ResponseWriter, user *User) error {
	nonce, err := a.createSession(user)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: nonce, Path: a.Path, HttpOnly: true})
	return nil
}

// The function destroySession ensures that the nonce is no longer valid.
//
// Note, this does not complete the logout on the client side.  The current
// Persona could easily reauthorize the user, so a complete logout will require
// action by the client as well, such as calling navigator.id.logout().
func (a *Policy) destroySession(nonce string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Do we have a client with that nonce?
	if client, ok := a.clientsByNonce[nonce]; ok {
		// remove client info from maps
		delete(a.clientsByNonce, nonce)
		delete(a.clientsByUser, client.username)
		// client info is still in the priority queue
		// however, it will be removed in due time when it expires
	}
}

// Logout ensures that the session associated with the HTTP request
// is no longer valid.  It then sets a header on the response to erase any cookies
// used by the client to identify the session.
//
// The caller is responsable for create an appropriate response to the HTTP request.
// For successful validation, redirection (http.StatusTemporaryRedirect) to the
// a login page or public content is most likely the correct response.
//
// If the credentials cannot be verified, an error is
// returned.  The caller is then responsable for creating an appropriate reponse to
// the HTTP request.
//
// Note, this does not complete the logout on the client side.  The current
// Persona could easily reauthorize the user, so a complete logout will require
// action by the client as well, such as calling navigator.id.logout().
func (a *Policy) Logout(w http.ResponseWriter, r *http.Request) error {
	// Find the nonce used to identify a client
	token, err := r.Cookie("Authorization")
	if err == nil && token.Value != "" {
		// Invalidate the nonce
		a.destroySession(token.Value)
	}

	// Clear the cookie from the client
	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: "", Path: a.Path, Expires: time.Unix(0, 0)})
	return nil
}
