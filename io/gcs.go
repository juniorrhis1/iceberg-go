// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package io

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"gocloud.dev/blob"
	"gocloud.dev/blob/gcsblob"
	"gocloud.dev/gcp"
	"google.golang.org/api/option"
)

// Constants for GCS configuration options
const (
	GCSEndpoint              = "gcs.endpoint"
	GCSKeyPath               = "gcs.keypath"
	GCSJSONKey               = "gcs.jsonkey"
	GCSCredType              = "gcs.credtype"
	GCSUseJsonAPI            = "gcs.usejsonapi" // set to anything to enable
	GCSOAuth2Token           = "gcs.oauth2.token"
	GCSOAuth2TokenExpiresAt  = "gcs.oauth2.token-expires-at"
	GCSOAuth2RefreshEnabled  = "gcs.oauth2.refresh-credentials-enabled"
	GCSOAuth2RefreshEndpoint = "gcs.oauth2.refresh-credentials-endpoint"
)

var allowedGCSCredTypes = map[string]option.CredentialsType{
	"service_account":              option.ServiceAccount,
	"authorized_user":              option.AuthorizedUser,
	"impersonated_service_account": option.ImpersonatedServiceAccount,
	"external_account":             option.ExternalAccount,
}

// ParseGCSConfig parses GCS properties and returns a configuration.
func ParseGCSConfig(props map[string]string) (*gcsblob.Options, gcp.TokenSource) {
	var o []option.ClientOption
	if url := props[GCSEndpoint]; url != "" {
		o = append(o, option.WithEndpoint(url))
	}
	var credType option.CredentialsType
	if key := props[GCSCredType]; key != "" {
		if ct, ok := allowedGCSCredTypes[key]; ok {
			credType = ct
		}
	}
	if key := props[GCSJSONKey]; key != "" {
		o = append(o, option.WithAuthCredentialsJSON(credType, []byte(key)))
	}
	if path := props[GCSKeyPath]; path != "" {
		o = append(o, option.WithAuthCredentialsFile(credType, path))
	}
	if _, ok := props[GCSUseJsonAPI]; ok {
		o = append(o, storage.WithJSONReads())
	}

	var tokenSource oauth2.TokenSource
	if token := props[GCSOAuth2Token]; token != "" {
		var expiry time.Time
		if expiresAtStr := props[GCSOAuth2TokenExpiresAt]; expiresAtStr != "" {
			if expiresAtInt, err := strconv.ParseInt(expiresAtStr, 10, 64); err == nil {
				expiry = time.Unix(expiresAtInt, 0)
			}
		}

		refreshEnabled := props[GCSOAuth2RefreshEnabled] == "true"
		refreshEndpoint := props[GCSOAuth2RefreshEndpoint]

		oauthToken := &oauth2.Token{
			AccessToken: token,
			TokenType:   "Bearer",
			Expiry:      expiry,
		}

		if refreshEnabled && refreshEndpoint != "" {
			if props["uri"] == "" {
				fmt.Println("Warning: GCS OAuth2 refresh enabled but 'uri' property is not set; refresh may fail")
			}

			tokenSource = oauth2.ReuseTokenSource(oauthToken, &refreshableTokenSource{
				token:      oauthToken,
				refreshURL: props["uri"] + "/" + refreshEndpoint,
				jsonKey:    props[GCSJSONKey],
				keyPath:    props[GCSKeyPath],
			})
		} else {
			tokenSource = oauth2.ReuseTokenSource(oauthToken, oauth2.StaticTokenSource(oauthToken))
		}
	}

	return &gcsblob.Options{
		ClientOptions: o,
	}, tokenSource
}

type storageCredential struct {
	Config map[string]string `json:"config"`
}

// refreshableTokenSource implements oauth2.TokenSource with refresh capability
type refreshableTokenSource struct {
	token      *oauth2.Token
	refreshURL string
	jsonKey    string
	keyPath    string
}

func (r *refreshableTokenSource) Token() (*oauth2.Token, error) {
	if r.token.Expiry.IsZero() || time.Until(r.token.Expiry) > time.Minute {
		return r.token, nil
	}

	req, err := http.NewRequest(http.MethodGet, r.refreshURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	token, err := r.getToken()
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("refresh endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		StorageCredentials []storageCredential `json:"storage-credentials"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	if len(result.StorageCredentials) == 0 {
		return nil, fmt.Errorf("refresh response missing storage credentials")
	}

	r.token.AccessToken = result.StorageCredentials[0].Config[GCSOAuth2Token]
	if expiresAtStr := result.StorageCredentials[0].Config[GCSOAuth2TokenExpiresAt]; expiresAtStr != "" {
		if expiresAtInt, err := strconv.ParseInt(expiresAtStr, 10, 64); err == nil {
			r.token.Expiry = time.Unix(expiresAtInt, 0)
		}
	}
	return r.token, nil
}

func (r *refreshableTokenSource) getToken() (*oauth2.Token, error) {
	if r.jsonKey != "" {
		jwtCfg, err := google.JWTConfigFromJSON(
			[]byte(r.jsonKey),
			"https://www.googleapis.com/auth/cloud-platform",
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse json key: %w", err)
		}
		jwtToken, err := jwtCfg.TokenSource(context.Background()).Token()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch jwt token: %w", err)
		}
		return jwtToken, nil
	}

	if r.keyPath != "" {
		creds, err := google.CredentialsFromJSON(
			context.Background(),
			[]byte(r.keyPath),
			"https://www.googleapis.com/auth/cloud-platform",
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key file: %w", err)
		}
		fileToken, err := creds.TokenSource.Token()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch file token: %w", err)
		}
		return fileToken, nil
	}

	return nil, fmt.Errorf("no credentials available for token refresh. Provide either json key or key path")
}

// Construct a GCS bucket from a URL
func createGCSBucket(ctx context.Context, parsed *url.URL, props map[string]string) (*blob.Bucket, error) {
	gcscfg, tokenSource := ParseGCSConfig(props)
	if tokenSource == nil {
		if creds, _ := gcp.DefaultCredentials(ctx); creds != nil {
			tokenSource = gcp.CredentialsTokenSource(creds)
		}
	}
	var client *gcp.HTTPClient
	if tokenSource == nil {
		client = gcp.NewAnonymousHTTPClient(gcp.DefaultTransport())
	} else {
		var err error
		client, err = gcp.NewHTTPClient(
			gcp.DefaultTransport(),
			tokenSource)
		if err != nil {
			return nil, err
		}
	}

	bucket, err := gcsblob.OpenBucket(ctx, client, parsed.Host, gcscfg)
	if err != nil {
		return nil, err
	}

	return bucket, nil
}
