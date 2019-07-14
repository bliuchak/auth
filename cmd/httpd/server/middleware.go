package Server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/zerolog"
)

type Middleware struct {
	jwtKey []byte
	logger zerolog.Logger
}

func NewMiddleware(jwtKey []byte, logger zerolog.Logger) *Middleware {
	return &Middleware{jwtKey: jwtKey, logger: logger}
}

func (m *Middleware) JWTValidation(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			m.logger.Warn().Str("token", r.Header.Get("Authorization")).Msg("no authorization header")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer") {
			m.logger.Warn().Str("token", r.Header.Get("Authorization")).Msg("no even a token")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			err := token.Claims.Valid()
			if err != nil {
				return nil, err
			}
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}

			return m.jwtKey, nil
		})

		if token != nil && token.Valid {
			m.logger.Info().Msg("token is valid")
			next.ServeHTTP(w, r)
		} else if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				m.logger.Warn().Msg("That's not even a token")
				w.WriteHeader(http.StatusBadRequest)
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				m.logger.Warn().Msg("token is either expired or not active yet")
				w.WriteHeader(http.StatusBadRequest)
			} else {
				m.logger.Error().Err(err).Msg("couldn't handle this token")
				w.WriteHeader(http.StatusUnauthorized)
			}
		} else {
			m.logger.Error().Err(err).Msg("couldn't handle this token")
			w.WriteHeader(http.StatusUnauthorized)
		}

	}

	return http.HandlerFunc(fn)
}
