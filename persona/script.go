// Copyright 2013 Robert W. Johnstone. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package persona

const (
	// ScriptUrl points to the Persona JavaScript library needed by the clients.
	ScriptUrl = "https://login.persona.org/include.js"
	// ScriptElement should be included in the body of the HTML response, preferably at the bottom of the page body.
	ScriptElement = `<script src="https://login.persona.org/include.js"></script>`
)
