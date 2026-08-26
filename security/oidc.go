package security

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/TwiN/logr"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

const (
	DefaultOIDCSessionTTL = 8 * time.Hour

	// bearerTokenValidationTimeout bounds how long a request may block while a bearer token that isn't already
	// cached locally is validated against the OIDC provider (JWKS or UserInfo endpoint).
	bearerTokenValidationTimeout = 10 * time.Second

	// opaqueAccessTokenCacheTTL is the maximum time an opaque access token (i.e. one validated through the
	// UserInfo endpoint rather than as a JWT) is cached locally. Unlike ID tokens, the OIDC spec doesn't guarantee
	// access tokens carry an inspectable expiry, so a short, fixed TTL is used instead of trusting SessionTTL, to
	// limit how long a token that was since revoked or expired at the provider keeps working against Gatus.
	opaqueAccessTokenCacheTTL = 5 * time.Minute
)

// OIDCConfig is the configuration for OIDC authentication
type OIDCConfig struct {
	IssuerURL       string        `yaml:"issuer-url"`   // e.g. https://dev-12345678.okta.com
	RedirectURL     string        `yaml:"redirect-url"` // e.g. http://localhost:8080/authorization-code/callback
	ClientID        string        `yaml:"client-id"`
	ClientSecret    string        `yaml:"client-secret"`
	Scopes          []string      `yaml:"scopes"`           // e.g. ["openid"]
	AllowedSubjects []string      `yaml:"allowed-subjects"` // e.g. ["user1@example.com"]. If empty, all subjects are allowed
	SessionTTL      time.Duration `yaml:"session-ttl"`      // e.g. 8h. Defaults to 8 hours

	oauth2Config oauth2.Config
	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
}

// ValidateAndSetDefaults returns whether the OIDC configuration is valid and sets default values.
func (c *OIDCConfig) ValidateAndSetDefaults() bool {
	if c.SessionTTL <= 0 {
		c.SessionTTL = DefaultOIDCSessionTTL
	}
	return len(c.IssuerURL) > 0 && len(c.RedirectURL) > 0 && strings.HasSuffix(c.RedirectURL, "/authorization-code/callback") && len(c.ClientID) > 0 && len(c.ClientSecret) > 0 && len(c.Scopes) > 0
}

func (c *OIDCConfig) initialize() error {
	provider, err := oidc.NewProvider(context.Background(), c.IssuerURL)
	if err != nil {
		return err
	}
	c.provider = provider
	c.verifier = provider.Verifier(&oidc.Config{ClientID: c.ClientID})
	// Configure an OpenID Connect aware OAuth2 client.
	c.oauth2Config = oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Scopes:       c.Scopes,
		RedirectURL:  c.RedirectURL,
		Endpoint:     provider.Endpoint(),
	}
	return nil
}

func (c *OIDCConfig) loginHandler(ctx *fiber.Ctx) error {
	state, nonce := uuid.NewString(), uuid.NewString()
	ctx.Cookie(&fiber.Cookie{
		Name:     cookieNameState,
		Value:    state,
		Path:     "/",
		MaxAge:   int(time.Hour.Seconds()),
		SameSite: "lax",
		HTTPOnly: true,
	})
	ctx.Cookie(&fiber.Cookie{
		Name:     cookieNameNonce,
		Value:    nonce,
		Path:     "/",
		MaxAge:   int(time.Hour.Seconds()),
		SameSite: "lax",
		HTTPOnly: true,
	})
	return ctx.Redirect(c.oauth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

func (c *OIDCConfig) callbackHandler(w http.ResponseWriter, r *http.Request) { // TODO: Migrate to a native fiber handler
	// Check if there's an error
	if len(r.URL.Query().Get("error")) > 0 {
		http.Error(w, r.URL.Query().Get("error")+": "+r.URL.Query().Get("error_description"), http.StatusBadRequest)
		return
	}
	// Ensure that the state has the expected value
	state, err := r.Cookie(cookieNameState)
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	// Validate token
	oauth2Token, err := c.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Error exchanging token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Missing 'id_token' in oauth2 token", http.StatusInternalServerError)
		return
	}
	idToken, err := c.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify id_token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Validate nonce
	nonce, err := r.Cookie(cookieNameNonce)
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}
	if !c.isSubjectAllowed(idToken.Subject) {
		logr.Debugf("[security.callbackHandler] Subject %s is not in the list of allowed subjects", idToken.Subject)
		http.Redirect(w, r, "/?error=access_denied", http.StatusFound)
		return
	}
	c.setSessionCookie(w, idToken)
	http.Redirect(w, r, "/", http.StatusFound)
}

// isSubjectAllowed returns whether the given subject is allowed to authenticate.
// If AllowedSubjects is empty, all subjects are allowed.
func (c *OIDCConfig) isSubjectAllowed(subject string) bool {
	if len(c.AllowedSubjects) == 0 {
		return true
	}
	for _, allowedSubject := range c.AllowedSubjects {
		if strings.EqualFold(allowedSubject, subject) {
			return true
		}
	}
	return false
}

// ValidateBearerToken validates a bearer token that was obtained directly from the OIDC provider (i.e. not through
// Gatus' own login flow) and thus isn't already backed by a local session. ID tokens (JWTs) are validated locally
// using the provider's JWKS, while opaque access tokens are validated by calling the provider's UserInfo endpoint,
// since the OIDC spec does not guarantee that access tokens are JWTs.
//
// On success, the token is cached locally under sessions so that subsequent requests using the same token don't need
// to reach out to the provider again for as long as the cached entry remains valid. The cache TTL never outlives
// the token itself: for ID tokens, it's capped by the token's own "exp" claim; for opaque access tokens, whose
// expiry Gatus has no way to inspect, a short fixed TTL is used instead.
func (c *OIDCConfig) ValidateBearerToken(ctx context.Context, token string) bool {
	if len(token) == 0 || c.verifier == nil || c.provider == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, bearerTokenValidationTimeout)
	defer cancel()
	var subject string
	var cacheTTL time.Duration
	if idToken, err := c.verifier.Verify(ctx, token); err == nil {
		subject = idToken.Subject
		cacheTTL = minDuration(time.Until(idToken.Expiry), c.SessionTTL)
	} else {
		userInfo, err := c.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
		if err != nil {
			logr.Debugf("[security.ValidateBearerToken] Failed to validate bearer token: %s", err.Error())
			return false
		}
		subject = userInfo.Subject
		cacheTTL = minDuration(opaqueAccessTokenCacheTTL, c.SessionTTL)
	}
	if !c.isSubjectAllowed(subject) {
		logr.Debugf("[security.ValidateBearerToken] Subject %s is not in the list of allowed subjects", subject)
		return false
	}
	if cacheTTL > 0 {
		sessions.SetWithTTL(token, subject, cacheTTL)
	}
	return true
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (c *OIDCConfig) setSessionCookie(w http.ResponseWriter, idToken *oidc.IDToken) {
	// At this point, the user has been confirmed. All that's left to do is create a session.
	sessionID := uuid.NewString()
	sessions.SetWithTTL(sessionID, idToken.Subject, c.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieNameSession,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(c.SessionTTL.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})
}
