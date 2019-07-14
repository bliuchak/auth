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

func NewTokens(jwtKey []byte, storage storage.Storager) *Tokens {
	return &Tokens{jwtKey: jwtKey, storage: storage}
}

func (t *Tokens) CreateToken(id uuid.UUID, email string, expiration time.Time) (storage.Token, error) {
	claims := &storage.Claims{
		ID:    id,
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expiration.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(t.jwtKey)
	if err != nil {
		return storage.Token{}, errors.Wrap(err, "can't sign token")
	}

	return storage.Token{
		Token: tokenString,
	}, nil
}
