package oidc_verify_middleware

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-collections/collections/set"
	"github.com/xenitab/go-oidc-middleware/oidctoken"
	"github.com/xenitab/go-oidc-middleware/options"
)

type EmailClaims struct {
	Email string `json:"email"`
}

func emailAllowedValidator(prefix string) options.ClaimsValidationFn[EmailClaims] {
	allow_env := strings.Split(os.Getenv(prefix+"SECURITY_ALLOW"), ",")
	allow_list := set.New()
	for _, s := range allow_env {
		allow_list.Insert(s)
	}
	return func(claims *EmailClaims) error {
		if len(claims.Email) < 1 {
			return fmt.Errorf("Token has no email claim.")
		}
		if allow_list.Has(claims.Email) {
			return nil
		} else {
			return fmt.Errorf("%s is not on the allow list", claims.Email)
		}
	}
}

func SetupOIDCMiddleware(prefix string) func(next func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	oidctok, err := oidctoken.New[EmailClaims](
		emailAllowedValidator(prefix),
		options.WithIssuer(os.Getenv(prefix+"SECURITY_ISSUER")),
		options.WithRequiredTokenType("JWT"),
		options.WithRequiredAudience(os.Getenv(prefix+"SECURITY_AUDIENCE")),
	)
	if err != nil {
		log.Panicf("Error creating token parser %+v\n", err)
	}
	oidcmiddle := func(next func(w http.ResponseWriter, r *http.Request)) func(w http.ResponseWriter, r *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				log.Printf("No bearer %s\n", auth)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, err = oidctok.ParseToken(r.Context(), auth[7:])
			if err != nil {
				log.Printf("Unauthorized %v\n", err)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	return oidcmiddle
}
