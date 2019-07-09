package users

import (
	"github.com/google/uuid"
	"github.com/ibliuchak/auth/internal/platform/storage"
	"golang.org/x/crypto/bcrypt"
)

type Users struct {
	storage storage.Storager
}

func NewUsers(storage storage.Storager) *Users {
	return &Users{storage: storage}
}

func (u *Users) CreateUser(email, password string) error {
	id := uuid.New()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	return u.storage.CreateUser(id, email, string(hashedPassword))
}

func (u *Users) GetUserByID(id string) (storage.User, error) {
	return u.storage.GetUserByID(id)
}

func (u *Users) GetUserByEmail(email string) (storage.User, error) {
	user, err := u.storage.GetUserByEmail(email)
	if err != nil {
		return storage.User{}, err
	}

	return user, nil
}
