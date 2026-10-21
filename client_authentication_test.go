// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/ory/fosite/internal/gen"

	"github.com/go-jose/go-jose/v3"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite/token/jwt"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

func mustGenerateRSAAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.RS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateECDSAAssertion(t *testing.T, claims jwt.MapClaims, key *ecdsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.ES256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func mustGenerateHSAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jose.HS256, claims)
	tokenString, err := token.SignedString([]byte("aaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccddddddddddddddddddddddd"))
	require.NoError(t, err)
	return tokenString
}

func mustGenerateNoneAssertion(t *testing.T, claims jwt.MapClaims, key *rsa.PrivateKey, kid string) string {
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return tokenString
}

// returns an http basic authorization header, encoded using application/x-www-form-urlencoded
func clientBasicAuthHeader(clientID, clientSecret string) http.Header {
	creds := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
	return http.Header{
		"Authorization": {
			"Basic " + base64.StdEncoding.EncodeToString([]byte(creds)),
		},
	}
}

func TestAuthenticateClient(t *testing.T) {
	const at = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	hasher := &BCrypt{Config: &Config{HashCost: 6}}
	f := &Fosite{
		Store: storage.NewMemoryStore(),
		Config: &Config{
			JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
			ClientSecretsHasher: hasher,
			TokenURL:            "token-url",
			HTTPClient:          retryablehttp.NewClient(),
		},
	}

	barSecret, err := hasher.Hash(context.TODO(), []byte("bar"))
	require.NoError(t, err)

	// a secret containing various special characters
	complexSecretRaw := "foo %66%6F%6F@$<§!✓"
	complexSecret, err := hasher.Hash(context.TODO(), []byte(complexSecretRaw))
	require.NoError(t, err)

	rsaKey := gen.MustRSAKey()
	rsaJwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &rsaKey.PublicKey,
			},
		},
	}

	ecdsaKey := gen.MustES256Key()
	ecdsaJwks := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID: "kid-foo",
				Use:   "sig",
				Key:   &ecdsaKey.PublicKey,
			},
		},
	}

	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewEncoder(w).Encode(rsaJwks))
	}
	ts := httptest.NewServer(h)
	defer ts.Close()

	for k, tc := range []struct {
		d             string
		client        *DefaultOpenIDConnectClient
		assertionType string
		assertion     string
		r             *http.Request
		form          url.Values
		expectErr     error
	}{
		{
			d:         "should fail because authentication can not be determined",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo"}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client does not exist",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"},
			form:      url.Values{"client_id": []string{"bar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass because client is public and authentication requirements are met",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"},
			form:   url.Values{"client_id": []string{"foo"}},
			r:      new(http.Request),
		},
		{
			d:      "should pass because client is public and client secret is empty in query param",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"},
			form:   url.Values{"client_id": []string{"foo"}, "client_secret": []string{""}},
			r:      new(http.Request),
		},
		{
			d:      "should pass because client is public and client secret is empty in basic auth header",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "none"},
			form:   url.Values{},
			r:      &http.Request{Header: clientBasicAuthHeader("foo", "")},
		},
		{
			d:         "should fail because client requires basic auth and client secret is empty in basic auth header",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "")},
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with client credentials containing special characters",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "!foo%20bar", Secret: complexSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:   url.Values{"client_id": []string{"!foo%20bar"}, "client_secret": []string{complexSecretRaw}},
			r:      new(http.Request),
		},
		{
			d:      "should pass with client credentials containing special characters via basic auth",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo — bar! +<&>*", Secret: complexSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:   url.Values{},
			r:      &http.Request{Header: clientBasicAuthHeader("foo — bar! +<&>*", complexSecretRaw)},
		},
		{
			d:         "should fail because auth method is not none",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Public: true}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{"client_id": []string{"foo"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass because client is confidential and id and secret match in post body",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: []byte("invalid_hash"), RotatedSecrets: [][]byte{barSecret}}, TokenEndpointAuthMethod: "client_secret_post"},
			form:   url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r:      new(http.Request),
		},
		{
			d:      "should pass because client is confidential and id and rotated secret match in post body",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:   url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r:      new(http.Request),
		},
		{
			d:         "should fail because client is confidential and secret does not match in post body",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:      url.Values{"client_id": []string{"foo"}, "client_secret": []string{"baz"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client is confidential and id does not exist in post body",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:      url.Values{"client_id": []string{"foo"}, "client_secret": []string{"bar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass because client is confidential and id and secret match in header",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:   url.Values{},
			r:      &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
		},
		{
			d:      "should pass because client is confidential and id and rotated secret match in header",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: []byte("invalid_hash"), RotatedSecrets: [][]byte{barSecret}}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:   url.Values{},
			r:      &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
		},
		{
			d:      "should pass because client is confidential and id and rotated secret match in header",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: []byte("invalid_hash"), RotatedSecrets: [][]byte{[]byte("invalid"), barSecret}}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:   url.Values{},
			r:      &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
		},
		{
			d:         "should fail because auth method is not client_secret_basic",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_post"},
			form:      url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "bar")},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client is confidential and secret does not match in header",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "baz")},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client is confidential and neither secret nor rotated does match in header",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret, RotatedSecrets: [][]byte{barSecret}}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: clientBasicAuthHeader("foo", "baz")},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client id is not encoded using application/x-www-form-urlencoded",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("%%%%%%:foo"))}}},
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client secret is not encoded using application/x-www-form-urlencoded",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:%%%%%%%"))}}},
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client is confidential and id does not exist in header",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, TokenEndpointAuthMethod: "client_secret_basic"},
			form:      url.Values{},
			r:         &http.Request{Header: http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("foo:bar"))}}},
			expectErr: ErrInvalidClient,
		},
		{
			d:         "should fail because client_assertion but client_assertion is missing",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "private_key_jwt"},
			form:      url.Values{"client_id": []string{"foo"}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
		},
		{
			d:         "should fail because client_assertion_type is unknown",
			client:    &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "foo", Secret: barSecret}, TokenEndpointAuthMethod: "private_key_jwt"},
			form:      url.Values{"client_id": []string{"foo"}, "client_assertion_type": []string{"foobar"}},
			r:         new(http.Request),
			expectErr: ErrInvalidRequest,
		},
		{
			d:      "should pass with proper RSA assertion when JWKs are set within the client and client_id is not set in the request",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should pass with proper ECDSA assertion when JWKs are set within the client and client_id is not set in the request",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: ecdsaJwks, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlgorithm: "ES256"},
			form: url.Values{"client_assertion": {mustGenerateECDSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, ecdsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because RSA assertion is used, but ECDSA assertion is required",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: ecdsaJwks, TokenEndpointAuthMethod: "private_key_jwt", TokenEndpointAuthSigningAlgorithm: "ES256"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because token auth method is not private_key_jwt, but client_secret_jwt",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "client_secret_jwt"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because token auth method is not private_key_jwt, but none",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "none"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because token auth method is not private_key_jwt, but client_secret_post",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "client_secret_post"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because token auth method is not private_key_jwt, but client_secret_basic",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "client_secret_basic"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because token auth method is not private_key_jwt, but foobar",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "foobar"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with proper assertion when JWKs are set within the client and client_id is not set in the request (aud is array)",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": []string{"token-url-2", "token-url"},
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because audience (array) does not match token url",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": []string{"token-url-1", "token-url-2"},
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with proper assertion when JWKs are set within the client",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because JWT algorithm is HS256",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateHSAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because JWT algorithm is none",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateNoneAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should pass with proper assertion when JWKs URI is set",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeysURI: ts.URL, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r: new(http.Request),
		},
		{
			d:      "should fail because client_assertion sub does not match client",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "not-bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because client_assertion iss does not match client",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "not-bar",
				"jti": "12345",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because client_assertion jti is not set",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"aud": "token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
		{
			d:      "should fail because client_assertion aud is not set",
			client: &DefaultOpenIDConnectClient{DefaultClient: &DefaultClient{ID: "bar", Secret: barSecret}, JSONWebKeys: rsaJwks, TokenEndpointAuthMethod: "private_key_jwt"},
			form: url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
				"sub": "bar",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iss": "bar",
				"jti": "12345",
				"aud": "not-token-url",
			}, rsaKey, "kid-foo")}, "client_assertion_type": []string{at}},
			r:         new(http.Request),
			expectErr: ErrInvalidClient,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.d), func(t *testing.T) {
			store := storage.NewMemoryStore()
			store.Clients[tc.client.ID] = tc.client
			f.Store = store

			c, err := f.AuthenticateClient(context.Background(), tc.r, tc.form)
			if tc.expectErr != nil {
				require.EqualError(t, err, tc.expectErr.Error())
				return
			}

			if err != nil {
				var validationError *jwt.ValidationError
				var rfcError *RFC6749Error
				if errors.As(err, &validationError) {
					t.Logf("Error is: %s", validationError.Inner)
				} else if errors.As(err, &rfcError) {
					t.Logf("DebugField is: %s", rfcError.DebugField)
					t.Logf("HintField is: %s", rfcError.HintField)
				}
			}
			require.NoError(t, err)
			assert.EqualValues(t, tc.client, c)
		})
	}
}

func TestAuthenticateClientTwice(t *testing.T) {
	const at = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	key := gen.MustRSAKey()
	client := &DefaultOpenIDConnectClient{
		DefaultClient: &DefaultClient{
			ID:     "bar",
			Secret: []byte("secret"),
		},
		JSONWebKeys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					KeyID: "kid-foo",
					Use:   "sig",
					Key:   &key.PublicKey,
				},
			},
		},
		TokenEndpointAuthMethod: "private_key_jwt",
	}
	store := storage.NewMemoryStore()
	store.Clients[client.ID] = client

	hasher := &BCrypt{&Config{HashCost: 6}}
	f := &Fosite{
		Store: store,
		Config: &Config{
			JWKSFetcherStrategy: NewDefaultJWKSFetcherStrategy(),
			ClientSecretsHasher: hasher,
			TokenURL:            "token-url",
		},
	}

	formValues := url.Values{"client_id": []string{"bar"}, "client_assertion": {mustGenerateRSAAssertion(t, jwt.MapClaims{
		"sub": "bar",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iss": "bar",
		"jti": "12345",
		"aud": "token-url",
	}, key, "kid-foo")}, "client_assertion_type": []string{at}}

	c, err := f.AuthenticateClient(context.Background(), new(http.Request), formValues)
	require.NoError(t, err, "%#v", err)
	assert.Equal(t, client, c)

	// replay the request and expect it to fail
	c, err = f.AuthenticateClient(context.Background(), new(http.Request), formValues)
	require.Error(t, err)
	assert.EqualError(t, err, ErrJTIKnown.Error())
	assert.Nil(t, c)
}

// A client lookup failure must remain distinguishable from invalid credentials.
type failingClientLookupStore struct {
	Storage
	err error
}

func (s failingClientLookupStore) GetClient(context.Context, string) (Client, error) {
	return nil, s.err
}

func TestAuthenticateClientLookupFailures(t *testing.T) {
	assertion := mustGenerateRSAAssertion(t, jwt.MapClaims{"sub": "lookup-client"}, gen.MustRSAKey(), "lookup-key")
	for _, method := range []string{"basic", "post", "public", "assertion", "authorize", "introspection"} {
		t.Run(method, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				cause error
				want  *RFC6749Error
			}{
				{"unknown-client", ErrNotFound, ErrInvalidClient},
				{"wrapped-unknown-client", fmt.Errorf("lookup: %w", ErrNotFound), ErrInvalidClient},
				{"canceled", context.Canceled, ErrTemporarilyUnavailable},
				{"deadline", context.DeadlineExceeded, ErrTemporarilyUnavailable},
				{"closed-database", sql.ErrConnDone, ErrTemporarilyUnavailable},
				{"connection-lost", io.EOF, ErrTemporarilyUnavailable},
				{"internal", errors.New("private storage diagnostic"), ErrTemporarilyUnavailable},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cause := fmt.Errorf("storage lookup: %w", tc.cause)
					f := &Fosite{Store: failingClientLookupStore{err: cause}, Config: &Config{}}
					request := httptest.NewRequest(http.MethodPost, "/token", nil)
					form := url.Values{"client_id": {"lookup-client"}}
					switch method {
					case "basic":
						request.SetBasicAuth("lookup-client", "private-secret")
					case "post":
						form.Set("client_secret", "private-secret")
					case "assertion":
						form.Set("client_assertion_type", clientAssertionTypeForTest)
						form.Set("client_assertion", assertion)
					}
					var err error
					switch method {
					case "authorize":
						request = httptest.NewRequest(http.MethodGet, "/authorize?client_id=lookup-client", nil)
						_, err = f.NewAuthorizeRequest(context.Background(), request)
					case "introspection":
						request = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader("token=private-token"))
						request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
						request.SetBasicAuth("lookup-client", "private-secret")
						_, err = f.NewIntrospectionRequest(context.Background(), request, nil)
						if errors.Is(tc.want, ErrInvalidClient) {
							tc.want = ErrRequestUnauthorized
						}
					default:
						var client Client
						client, err = f.AuthenticateClient(context.Background(), request, form)
						require.Nil(t, client)
					}
					require.ErrorIs(t, err, tc.want)
					require.ErrorIs(t, err, tc.cause)
					response := httptest.NewRecorder()
					f.WriteAccessError(context.Background(), response, nil, err)
					assert.Equal(t, tc.want.CodeField, response.Code)
					var payload map[string]interface{}
					require.NoError(t, json.Unmarshal(response.Body.Bytes(), &payload))
					assert.Equal(t, tc.want.ErrorField, payload["error"])
					assert.NotContains(t, response.Body.String(), "private-secret")
					assert.NotContains(t, response.Body.String(), "storage lookup")
					assert.NotContains(t, response.Body.String(), "private storage diagnostic")
					assert.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				})
			}
		})
	}
}

const clientAssertionTypeForTest = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
