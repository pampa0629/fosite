// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/ory/fosite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuppressingProtocolWritersPreserveServerFailures(t *testing.T) {
	f := &Fosite{Config: &Config{}}
	for name, write := range map[string]func(context.Context, http.ResponseWriter, error){
		"revocation":    f.WriteRevocationResponse,
		"introspection": f.WriteIntrospectionError,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				err    error
				status int
				code   string
			}{
				{"unavailable", fmt.Errorf("wrapped: %w", ErrTemporarilyUnavailable.WithWrap(errors.New("private database fault"))), 503, "temporarily_unavailable"},
				{"server-error", ErrServerError.WithWrap(errors.New("private database fault")), 500, "server_error"},
				{"raw-storage-error", errors.New("private database fault"), 500, "server_error"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					response := httptest.NewRecorder()
					write(context.Background(), response, tc.err)
					require.Equal(t, tc.status, response.Code)
					var payload map[string]interface{}
					require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
					assert.Equal(t, tc.code, payload["error"])
					assert.NotContains(t, response.Body.String(), "private database fault")
					assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				})
			}
			for _, cause := range []error{nil, ErrNotFound, fmt.Errorf("wrapped: %w", ErrNotFound), ErrInactiveToken} {
				response := httptest.NewRecorder()
				write(context.Background(), response, cause)
				assert.Equal(t, http.StatusOK, response.Code)
			}
		})
	}
}
