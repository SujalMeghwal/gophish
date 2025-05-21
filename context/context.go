//go:build go1.7
// +build go1.7

package context

import (
	"context"
	"net/http"
)

// Get retrieves a value from the request's context by key.
func Get(r *http.Request, key interface{}) interface{} {
	return r.Context().Value(key)
}

// Set returns a new request with the given key-value pair stored in its context.
// If val is nil, it returns the original request unchanged.
func Set(r *http.Request, key, val interface{}) *http.Request {
	if val == nil {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), key, val))
}

// Clear is a no-op because context cleanup is automatic in Go 1.7+.
func Clear(r *http.Request) {}
