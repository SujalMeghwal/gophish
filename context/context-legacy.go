//go:build !go1.7
// +build !go1.7

package context

import (
	"net/http"

	"github.com/gorilla/context"
)

// Get retrieves a value associated with the key from the request's context store.
func Get(r *http.Request, key interface{}) interface{} {
	return context.Get(r, key)
}

// Set stores a key-value pair in the request's context store.
// Returns the original request, since gorilla/context stores values separately.
func Set(r *http.Request, key, val interface{}) *http.Request {
	if val == nil {
		return r
	}
	context.Set(r, key, val)
	return r
}

// Clear removes all values stored in the request's context store.
// Should be called when the request is finished to avoid memory leaks.
func Clear(r *http.Request) {
	context.Clear(r)
}
