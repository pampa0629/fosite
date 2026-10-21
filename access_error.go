// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
)

// Convert an error to an http response as per RFC6749
func (f *Fosite) WriteAccessError(ctx context.Context, rw http.ResponseWriter, req Requester, err error) {
	f.writeJsonError(ctx, rw, req, err)
}

func (f *Fosite) writeJsonError(ctx context.Context, rw http.ResponseWriter, requester Requester, err error) {
	rw.Header().Set("Content-Type", "application/json;charset=UTF-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	rfcerr := ErrorToRFC6749Error(err).WithLegacyFormat(f.Config.GetUseLegacyErrorFormat(ctx)).WithExposeDebug(f.Config.GetSendDebugMessagesToClients(ctx))

	if requester != nil {
		rfcerr = rfcerr.WithLocalizer(f.Config.GetMessageCatalog(ctx), getLangFromRequester(requester))
	}

	js, err := json.Marshal(rfcerr)
	if err != nil {
		if f.Config.GetSendDebugMessagesToClients(ctx) {
			errorMessage := EscapeJSONString(err.Error())
			http.Error(rw, fmt.Sprintf(`{"error":"server_error","error_description":"%s"}`, errorMessage), http.StatusInternalServerError)
		} else {
			http.Error(rw, `{"error":"server_error"}`, http.StatusInternalServerError)
		}
		return
	}

	rw.WriteHeader(rfcerr.CodeField)
	// ignoring the error because the connection is broken when it happens
	_, _ = rw.Write(js)
}

// writeServerError prevents writers that suppress expected protocol failures
// from reporting an unavailable service as successful revocation/inactivity.
func (f *Fosite) writeServerError(ctx context.Context, rw http.ResponseWriter, err error) bool {
	var protocolError *RFC6749Error
	if !errors.As(err, &protocolError) {
		if errors.Is(err, ErrNotFound) {
			return false
		}
		protocolError = ErrServerError.WithWrap(err).WithDebug(err.Error())
	}
	if protocolError.CodeField < http.StatusInternalServerError {
		return false
	}
	f.writeJsonError(ctx, rw, nil, protocolError)
	return true
}
