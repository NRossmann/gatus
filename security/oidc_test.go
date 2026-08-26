package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestOIDCConfig_ValidateAndSetDefaults(t *testing.T) {
	c := &OIDCConfig{
		IssuerURL:       "https://sso.gatus.io/",
		RedirectURL:     "http://localhost:80/authorization-code/callback",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid"},
		AllowedSubjects: []string{"user1@example.com"},
		SessionTTL:      0, // Not set! ValidateAndSetDefaults should set it to DefaultOIDCSessionTTL
	}
	if !c.ValidateAndSetDefaults() {
		t.Error("OIDCConfig should be valid")
	}
	if c.SessionTTL != DefaultOIDCSessionTTL {
		t.Error("expected SessionTTL to be set to DefaultOIDCSessionTTL")
	}
}

func TestOIDCConfig_callbackHandler(t *testing.T) {
	c := &OIDCConfig{
		IssuerURL:       "https://sso.gatus.io/",
		RedirectURL:     "http://localhost:80/authorization-code/callback",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid"},
		AllowedSubjects: []string{"user1@example.com"},
	}
	if err := c.initialize(); err != nil {
		t.Fatal("expected no error, but got", err)
	}
	// Try with no state cookie
	request, _ := http.NewRequest("GET", "/authorization-code/callback", nil)
	responseRecorder := httptest.NewRecorder()
	c.callbackHandler(responseRecorder, request)
	if responseRecorder.Code != http.StatusBadRequest {
		t.Error("expected code to be 400, but was", responseRecorder.Code)
	}
	// Try with state cookie
	request, _ = http.NewRequest("GET", "/authorization-code/callback", nil)
	request.AddCookie(&http.Cookie{Name: cookieNameState, Value: "fake-state"})
	responseRecorder = httptest.NewRecorder()
	c.callbackHandler(responseRecorder, request)
	if responseRecorder.Code != http.StatusBadRequest {
		t.Error("expected code to be 400, but was", responseRecorder.Code)
	}
	// Try with state cookie and state query parameter
	request, _ = http.NewRequest("GET", "/authorization-code/callback?state=fake-state", nil)
	request.AddCookie(&http.Cookie{Name: cookieNameState, Value: "fake-state"})
	responseRecorder = httptest.NewRecorder()
	c.callbackHandler(responseRecorder, request)
	// Exchange should fail, so 500.
	if responseRecorder.Code != http.StatusInternalServerError {
		t.Error("expected code to be 500, but was", responseRecorder.Code)
	}
}

func TestOIDCConfig_isSubjectAllowed(t *testing.T) {
	scenarios := []struct {
		Name            string
		AllowedSubjects []string
		Subject         string
		ExpectAllowed   bool
	}{
		{Name: "no-allowed-subjects", AllowedSubjects: nil, Subject: "user1@example.com", ExpectAllowed: true},
		{Name: "matching-subject", AllowedSubjects: []string{"user1@example.com"}, Subject: "user1@example.com", ExpectAllowed: true},
		{Name: "matching-subject-different-case", AllowedSubjects: []string{"User1@Example.com"}, Subject: "user1@example.com", ExpectAllowed: true},
		{Name: "non-matching-subject", AllowedSubjects: []string{"user1@example.com"}, Subject: "user2@example.com", ExpectAllowed: false},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			c := &OIDCConfig{AllowedSubjects: scenario.AllowedSubjects}
			if allowed := c.isSubjectAllowed(scenario.Subject); allowed != scenario.ExpectAllowed {
				t.Errorf("expected isSubjectAllowed to return %v, got %v", scenario.ExpectAllowed, allowed)
			}
		})
	}
}

func TestOIDCConfig_ValidateBearerToken(t *testing.T) {
	c := &OIDCConfig{
		IssuerURL:       "https://sso.gatus.io/",
		RedirectURL:     "http://localhost:80/authorization-code/callback",
		ClientID:        "client-id",
		ClientSecret:    "client-secret",
		Scopes:          []string{"openid"},
		AllowedSubjects: []string{"user1@example.com"},
	}
	if err := c.initialize(); err != nil {
		t.Fatal("expected no error, but got", err)
	}
	// An empty token should be rejected without reaching out to the provider
	if c.ValidateBearerToken(context.Background(), "") {
		t.Error("expected empty token to be rejected")
	}
	// A token that is neither a valid ID token nor a valid access token according to the provider should be rejected
	if c.ValidateBearerToken(context.Background(), "this-is-not-a-valid-token") {
		t.Error("expected invalid token to be rejected")
	}
	// The invalid token should not have created a session
	if _, exists := sessions.Get("this-is-not-a-valid-token"); exists {
		t.Error("expected no session to be created for an invalid token")
	}
}

func TestMinDuration(t *testing.T) {
	scenarios := []struct {
		Name     string
		A, B     time.Duration
		Expected time.Duration
	}{
		{Name: "a-smaller", A: time.Minute, B: time.Hour, Expected: time.Minute},
		{Name: "b-smaller", A: time.Hour, B: time.Minute, Expected: time.Minute},
		{Name: "equal", A: time.Minute, B: time.Minute, Expected: time.Minute},
		{Name: "negative-a", A: -time.Minute, B: time.Hour, Expected: -time.Minute},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			if result := minDuration(scenario.A, scenario.B); result != scenario.Expected {
				t.Errorf("expected %v, got %v", scenario.Expected, result)
			}
		})
	}
}

func TestOIDCConfig_setSessionCookie(t *testing.T) {
	c := &OIDCConfig{}
	responseRecorder := httptest.NewRecorder()
	c.setSessionCookie(responseRecorder, &oidc.IDToken{Subject: "test@example.com"})
	if len(responseRecorder.Result().Cookies()) == 0 {
		t.Error("expected cookie to be set")
	}
}

func TestOIDCConfig_setSessionCookieWithCustomTTL(t *testing.T) {
	customTTL := 30 * time.Minute
	c := &OIDCConfig{SessionTTL: customTTL}
	responseRecorder := httptest.NewRecorder()
	c.setSessionCookie(responseRecorder, &oidc.IDToken{Subject: "test@example.com"})
	cookies := responseRecorder.Result().Cookies()
	if len(cookies) == 0 {
		t.Error("expected cookie to be set")
	}
	sessionCookie := cookies[0]
	if sessionCookie.MaxAge != int(customTTL.Seconds()) {
		t.Errorf("expected cookie MaxAge to be %d, but was %d", int(customTTL.Seconds()), sessionCookie.MaxAge)
	}
}
