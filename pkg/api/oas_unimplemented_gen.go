// Code generated by ogen, DO NOT EDIT.

package api

import (
	"context"

	ht "github.com/ogen-go/ogen/http"
)

// UnimplementedHandler is no-op Handler which returns http.ErrNotImplemented.
type UnimplementedHandler struct{}

var _ Handler = UnimplementedHandler{}

// CreateSession implements createSession operation.
//
// Create Session.
//
// POST /sessions
func (UnimplementedHandler) CreateSession(ctx context.Context, req *CreateSessionRequestSchema) (r CreateSessionRes, _ error) {
	return r, ht.ErrNotImplemented
}

// SubmitPassword implements submitPassword operation.
//
// Submit Password.
//
// POST /passwords
func (UnimplementedHandler) SubmitPassword(ctx context.Context, req *SubmitPasswordRequestSchema) (r SubmitPasswordRes, _ error) {
	return r, ht.ErrNotImplemented
}
