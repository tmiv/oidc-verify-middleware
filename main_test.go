package oidc_verify_middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func Test_emailAllowedValidator(t *testing.T) {
	os.Setenv("SECURITY_ALLOW", "test@example.com,test2@example.com")
	result := emailAllowedValidator("")
	if result == nil {
		t.Errorf("emailAllowedValidator() expected return")
	}
	ec := EmailClaims{}
	ec.Email = "test@example.com"
	if result(&ec) != nil {
		t.Errorf("emailAllowedValidator() expected nil")
	}
	ec.Email = "test2@example.com"
	if result(&ec) != nil {
		t.Errorf("emailAllowedValidator() expected nil")
	}
	ec.Email = "test3@example.com"
	if result(&ec) == nil {
		t.Errorf("emailAllowedValidator() expected error")
	}
}

func TestSetupOIDCMiddleware(t *testing.T) {
	t.Run("No Issuer", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("SetupOIDCMiddleware didn't panic")
			}
		}()

		SetupOIDCMiddleware("PREFIX_")
	})
	os.Setenv("PREFIX_SECURITY_ISSUER", "https://accounts.google.com")
	middleware_builder := SetupOIDCMiddleware("PREFIX_")
	if middleware_builder == nil {
		t.Errorf("Middleware Builder should have been returned")
	}
	fakenext := func(w http.ResponseWriter, r *http.Request) {}
	middleware := middleware_builder(fakenext)
	if middleware == nil {
		t.Errorf("Middleware should have been returned")
	}
	req, err := http.NewRequest("GET", "/nothing", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	middleware(rr, req)
	if rr.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("Middleware should have returned Unauthorized")
	}
	rr = httptest.NewRecorder()
	req.Header.Add("Authorization", "Bearer quack")
	middleware(rr, req)
	if rr.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("Middleware should have returned Unauthorized")
	}
}
