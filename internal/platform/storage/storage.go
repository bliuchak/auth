package storage

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type Storager interface {
	CreateUser(id uuid.UUID, email, hashedPassword string) error
	GetUserByID(id string) (User, error)
	GetUserByEmail(email string) (User, error)
}

type User struct {
	ID       uuid.UUID
	Email    string
	Password string
}

type Token struct {
	Token  string
	Claims Claims
}

type Claims struct {
	ID    uuid.UUID
	Email string
	jwt.StandardClaims
}
