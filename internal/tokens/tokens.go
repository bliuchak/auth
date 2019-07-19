package tokens

import (
	"time"

	"github.com/pkg/errors"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	"github.com/ibliuchak/auth/internal/platform/storage"
)

type Tokens struct {
	jwtKey  []byte
	storage storage.Storager
}

type token struct {
	Token  string
	Claims claims
}

type claims struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	jwt.StandardClaims
}

func NewTokens(jwtKey []byte, storage storage.Storager) *Tokens {
	return &Tokens{jwtKey: jwtKey, storage: storage}
}

func (t *Tokens) CreateToken(id uuid.UUID, email string, expiration time.Time) (token, error) {
	claims := &claims{
		ID:    id.String(),
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}

	tokenWithClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := tokenWithClaims.SignedString(t.jwtKey)
	if err != nil {
		return token{}, errors.Wrap(err, "can't sign token")
	}

	return token{
		Token: tokenString,
	}, nil
}
