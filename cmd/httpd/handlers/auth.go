package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ibliuchak/auth/internal/platform/storage"

	"github.com/ibliuchak/auth/internal/tokens"

	"golang.org/x/crypto/bcrypt"

	"github.com/ibliuchak/auth/internal/users"

	"github.com/rs/zerolog"
)

type Auth struct {
	logger zerolog.Logger
	users  users.Users
	tokens tokens.Tokens
}

func NewAuth(logger zerolog.Logger, users users.Users, tokens tokens.Tokens) *Auth {
	return &Auth{logger: logger, users: users, tokens: tokens}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token string `json:"token"`
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		a.logger.Error().Err(err).Msg("Unable to decode login data")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	user, err := a.users.GetUserByEmail(request.Email)
	if err != nil {
		if err == storage.ErrUserNotFound {
			a.logger.Error().Err(err).Str("email", request.Email).Msg("user not found")

			w.WriteHeader(http.StatusNotFound)
			return
		}
		a.logger.Error().Err(err).Str("email", request.Email).Msg("Can't get user")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		a.logger.Error().Err(err).Str("email", user.Email).Msg("Bad password")

		w.WriteHeader(http.StatusForbidden)
		return
	}

	a.logger.Info().Str("email", user.Email).Msg("Successful login")

	expiration := time.Now().Add(1 * time.Hour)
	token, err := a.tokens.CreateToken(user.ID, user.Email, expiration)
	if err != nil {
		a.logger.Error().Err(err).Str("email", request.Email).Msg("can't create token")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	a.logger.Info().Str("email", user.Email).Time("exp", expiration).Msg("New token issued")

	resp := loginResponse{
		Token: token.Token,
	}

	w.WriteHeader(http.StatusAccepted)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(resp); err != nil {
		a.logger.Error().Err(err).Msg("Encoder error")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (a *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID").(string)
	email := r.Context().Value("email").(string)

	uuid, err := uuid.Parse(userID)
	if err != nil {
		a.logger.Warn().
			Err(err).
			Str("email", email).
			Msg("can't parse uuid from context claims")

		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expiration := time.Now().Add(1 * time.Hour)
	token, err := a.tokens.CreateToken(uuid, email, expiration)
	if err != nil {
		a.logger.Error().
			Err(err).
			Str("email", email).
			Msg("can't create token")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	a.logger.Info().
		Str("email", email).
		Time("exp", expiration).
		Msg("token refreshed")

	resp := loginResponse{
		Token: token.Token,
	}

	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(resp); err != nil {
		a.logger.Error().
			Err(err).
			Msg("Encoder error")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
