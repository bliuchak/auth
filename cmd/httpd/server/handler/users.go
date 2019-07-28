package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/ibliuchak/auth/internal/platform/storage"

	"github.com/ibliuchak/auth/internal/users"

	"github.com/rs/zerolog"
)

type Users struct {
	logger *zerolog.Logger
	users  users.Users
}

func NewUsers(logger *zerolog.Logger, users users.Users) *Users {
	return &Users{logger: logger, users: users}
}

type createUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type userPublic struct {
	Email string `json:"email"`
}

func (u *Users) GetUserByID(w http.ResponseWriter, r *http.Request) {
	// TODO: validate incoming parameter
	userID := chi.URLParam(r, "userID")

	user, err := u.users.GetUserByID(userID)
	if err != nil {
		if err == storage.ErrUserNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		u.logger.Error().Err(err).Str("user_id", userID).Msg("error occurred on getting user")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	userPublic := userPublic{
		Email: user.Email,
	}

	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(userPublic); err != nil {
		u.logger.Error().Err(err).Msg("Encoder error")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (u *Users) CreateUser(w http.ResponseWriter, r *http.Request) {
	var request createUserRequest

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		u.logger.Error().Err(err).Msg("Unable to decode user data")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = u.users.CreateUser(request.Email, request.Password)
	if err == storage.ErrUserEmailExists {
		u.logger.Warn().Err(err).Str("email", request.Email).Msg("email already existing")
		w.WriteHeader(http.StatusConflict)
		return
	} else if err != nil {
		u.logger.Error().Err(err).Str("email", request.Email).Msg("fail to create user")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	u.logger.Info().Str("email", request.Email).Msg("New user created")
	w.WriteHeader(http.StatusCreated)
}
