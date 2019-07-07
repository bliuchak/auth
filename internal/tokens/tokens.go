package tokens

import (
	"time"

	"github.com/pkg/errors"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	"github.com/ibliuchak/auth/internal/platform/storage"
)

// TODO take it from config or ENV
var jwtKey = []byte("my_secret_key")

type Tokens struct {
	storage storage.Storager
}

func NewTokens(storage storage.Storager) *Tokens {
	return &Tokens{storage: storage}
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

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return storage.Token{}, errors.Wrap(err, "can't sign token")
	}

	if err := t.storage.CreateToken(tokenString, *claims); err != nil {
		return storage.Token{}, err
	}

	return storage.Token{
		Token: tokenString,
	}, nil
}

func (t *Tokens) GetNotExpiredTokenByToken(token string) (storage.Token, error) {
	return t.storage.GetNotExpiredTokenByToken(token)
}

func (t *Tokens) DeprecateToken(token storage.Token) error {
	return t.storage.DeprecateToken(token)
}
