package server

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog"
)

type Middleware struct {
	jwtKey []byte
	logger zerolog.Logger
}

type key int

const (
	KeyUserID key = iota
	KeyEmail
)

var (
	ErrClaimsIDMissed    = errors.New("missed user ID in claims")
	ErrClaimsEmailMissed = errors.New("missed user email in claims")
	ErrClaimsExpMissed   = errors.New("missed exp in claims")
)

func NewMiddleware(jwtKey []byte, logger zerolog.Logger) *Middleware {
	return &Middleware{jwtKey: jwtKey, logger: logger}
}

func (m *Middleware) JWTValidation(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			m.logger.Warn().Str("token", r.Header.Get("Authorization")).Msg("no authorization header")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer") {
			m.logger.Warn().Str("token", r.Header.Get("Authorization")).Msg("not even a token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			err := token.Claims.Valid()
			if err != nil {
				return nil, err
			}

			claims := token.Claims.(jwt.MapClaims)
			if _, ok := claims["id"]; !ok {
				return nil, ErrClaimsIDMissed
			}
			if _, ok := claims["email"]; !ok {
				return nil, ErrClaimsEmailMissed
			}
			if _, ok := claims["exp"]; !ok {
				return nil, ErrClaimsExpMissed
			}

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return m.jwtKey, nil
		})

		if token != nil && token.Valid {
			claims := token.Claims.(jwt.MapClaims)

			sec, dec := math.Modf(claims["exp"].(float64))

			m.logger.Info().
				Interface("user_id", claims["id"]).
				Str("exp", time.Unix(int64(sec), int64(dec*(1e9))).Format(time.RFC3339)).
				Msg("token is validated by middleware")

			ctx := context.WithValue(r.Context(), KeyUserID, claims["id"].(string))
			ctx = context.WithValue(ctx, KeyEmail, claims["email"].(string))

			next.ServeHTTP(w, r.WithContext(ctx))
		} else {
			m.logger.Error().Err(err).Msg("couldn't handle this token")
			w.WriteHeader(http.StatusForbidden)
		}

	}

	return http.HandlerFunc(fn)
}
