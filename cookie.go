// Copyright 2014 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httpauth

import (
	"container/heap"
	"errors"
	"html"
	"net/http"
	"sync"
	"time"
)

// The following variables are used to specify error conditions for this
// package.
var (
	ErrBadUsernameOrPassword = errors.New("Bad username or password.")
	ErrInvalidToken          = errors.New("The session token was invalid.")
)

type cookieClientInfo struct {
	username    string // username for this authorized connection
	lastContact int64  // time of last communication with this client (unix nanoseconds)
	nonce       string // unique per client salt
}

type cookiePriorityQueue []*cookieClientInfo

func (pq cookiePriorityQueue) Len() int {
	return len(pq)
}

func (pq cookiePriorityQueue) Less(i, j int) bool {
	return pq[i].lastContact < pq[j].lastContact
}

func (pq cookiePriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *cookiePriorityQueue) Push(x interface{}) {
	*pq = append(*pq, x.(*cookieClientInfo))
}

func (pq *cookiePriorityQueue) Pop() interface{} {
	n := len(*pq)
	ret := (*pq)[n-1]
	*pq = (*pq)[:n-1]
	return ret
}

func (pq cookiePriorityQueue) MinValue() int64 {
	n := len(pq)
	return pq[n-1].lastContact
}

// A Cookie is a policy for authenticating users that uses a cookie stored
// on the client to verify authorized clients.  This authentication scheme
// is more involved than the others, as callers will need to implement URLs
// for login and logout pages.
//
// When a user successfully logs in, a token (nonce) is saved in a cookie.
// The presence and validity of that token is verified to authorize future
// HTTP requests.  The tokens can also be invalidated to logout a users.
type Cookie struct {
	// Realm provides a 'namespace' where the authentication will be considered.
	Realm string
	// Auth provides a function or closure that can validate if a username/password combination is valid
	Auth Authenticator
	// Clients are redirected to the LoginPage when they don't have authorization
	LoginPage string
	// Path sets the scope of the authorization cookie
	Path string
	// RequireXsrfHeader adds an additional verification.  See function VerifyXsrfHeader.
	RequireXsrfHeader bool

	// CientCacheResidence controls how long client information is retained
	ClientCacheResidence time.Duration

	mutex          sync.Mutex
	clientsByNonce map[string]*cookieClientInfo
	clientsByUser  map[string]*cookieClientInfo
	lru            cookiePriorityQueue
}

// NewCookie creates a new authentication policy that uses the cookie authentication scheme.
func NewCookie(realm, loginPageUrl string, auth Authenticator) *Cookie {
	return &Cookie{
		realm,
		auth,
		loginPageUrl,
		"/",
		false,
		DefaultClientCacheResidence,
		sync.Mutex{},
		make(map[string]*cookieClientInfo),
		make(map[string]*cookieClientInfo),
		nil}
}

func (a *Cookie) evictLeastRecentlySeen() {
	now := time.Now().UnixNano()

	// Remove all entries from the client cache older than the
	// residence time.
	for len(a.lru) > 0 && a.lru.MinValue()+a.ClientCacheResidence.Nanoseconds() <= now {
		client := heap.Pop(&a.lru).(*cookieClientInfo)
		delete(a.clientsByNonce, client.nonce)
		delete(a.clientsByUser, client.username)
	}
}

// Authorize retrieves the credientials from the HTTP request, and
// returns the username only if the credientials could be validated.
// If the return value is blank, then the credentials are missing,
// invalid, or a system error prevented verification.
func (a *Cookie) Authorize(r *http.Request) (username string) {
	// Verify XSRF header
	if a.RequireXsrfHeader && !VerifyXsrfHeader(r) {
		return ""
	}

	// Find the nonce used to identify a client
	token, err := r.Cookie("Authorization")
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
func (a *Cookie) NotifyAuthRequired(w http.ResponseWriter, r *http.Request) {
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

// The function createSession checks the credentials of a client, and, if
// valid, creates a client entry.  The nonce can be used by the client to
// identify the session.
//
// This functions handles internal details of creating the session only.
// The caller is still responsible for creating the HTTP response, which
// will need to save the returned nonce.
//
// If the credentials cannot be verified, an error will be returned (ErrBadUsernameOrPassword).
func (a *Cookie) createSession(username, password string) (nonce string, err error) {
	// Authorize the user
	if !a.Auth(username, password) {
		return "", ErrBadUsernameOrPassword
	}

	// Create an entry for this user
	nonce, err = createNonce()
	if err != nil {
		return "", err
	}

	// Lock before mutating the fields of the policy
	a.mutex.Lock()
	defer a.mutex.Unlock()

	// Check if there is already a session for this username
	if ci, ok := a.clientsByUser[username]; ok {
		ci.lastContact = time.Now().UnixNano()
		return ci.nonce, nil
	}

	ci := &cookieClientInfo{username, time.Now().UnixNano(), nonce}
	a.clientsByNonce[nonce] = ci
	a.clientsByUser[username] = ci

	return nonce, nil
}

// Login checks the credentials (a username/password pair) of the client.
// If successful, a session is created, and then a cookie is set on the
// HTTP response so that the client can access the session in future
// HTTP requests.
//
// The caller is responsable for creating an appropriate response body for
// the HTTP request. For successful validation, redirection (http.StatusTemporaryRedirect)
// to the protected content is most likely the correct response.
//
// If the credentials cannot be verified, an error (ErrBadUsernameOrPassword)
// is returned.  Other errors are possible.  The caller is then responsable
// for creating an appropriate reponse to the HTTP request.
func (a *Cookie) Login(w http.ResponseWriter, username, password string) error {
	nonce, err := a.createSession(username, password)
	if err != nil {
		return err
	}

	// There is no reason for client-side code to access the nonce.  Therefore,
	// we will set the cookie as HttpOnly.
	// We should also consider setting the cookie as secure, and restrict
	// it to HTTPS connections.  However, some library users might be
	// using HTTP, and the nonce should (at minimum) be safe against
	// replay attacks.
	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: nonce, Path: a.Path, HttpOnly: true})
	return nil
}

// The function destroySession ensures that the nonce is no longer valid.
func (a *Cookie) destroySession(nonce string) {
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
// is no longer valid.  It then sets a header on the response to erase any
// cookies used by the client to identify the session.  However, even if
// future HTTP requests contains the cookie, the call to Authorize will
// fail.
//
// The caller is responsable for create an appropriate response body for the HTTP request.
// When the function is successful, redirection (http.StatusTemporaryRedirect) to the
// a login page or public content is most likely the correct response.
//
// If the credentials cannot be verified, an error is
// returned.  The caller is then responsable for creating an appropriate reponse to
// the HTTP request.
func (a *Cookie) Logout(w http.ResponseWriter, r *http.Request) error {
	// Find the nonce used to identify a client
	token, err := r.Cookie("Authorization")
	if err == nil || token.Value != "" {
		// Invalidate the nonce
		a.destroySession(token.Value)
	}

	// Clear the cookie from the client
	http.SetCookie(w, &http.Cookie{Name: "Authorization", Value: "", Path: a.Path, Expires: time.Unix(0, 0)})
	return nil
}
