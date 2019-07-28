package storage

import (
	"errors"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrUserEmailExists = errors.New("user email already existing")
)

type Storager interface {
	CreateUser(id uuid.UUID, email, hashedPassword string) error
	GetUserByID(id string) (User, error)
	GetUserByEmail(email string) (User, error)
}

type User struct {
	ID       uuid.UUID `json:"id"`
	Email    string    `json:"email"`
	Password string    `json:"password"`
}
