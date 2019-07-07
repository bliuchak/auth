package handlers

import (
	"encoding/json"
	"net/http"
	"time"

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

type validateTokenRequest struct {
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
		a.logger.Error().Err(err).Str("email", request.Email).Msg("Can't get user")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// compare request password and record password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		a.logger.Error().Err(err).Str("email", user.Email).Msg("Bad password")

		w.WriteHeader(http.StatusForbidden)
		return
	}

	a.logger.Info().Str("email", user.Email).Msg("Successful login")

	expiration := time.Now().Add(30 * time.Minute)
	token, err := a.tokens.CreateToken(user.ID, user.Email, expiration)
	if err != nil {
		a.logger.Error().Err(err).Str("email", request.Email).Msg("can't create token")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	a.logger.Info().Str("token", token.Token).Time("exp", expiration).Msg("New token issued")

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
	var request validateTokenRequest

	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		a.logger.Error().Err(err).Msg("Unable to decode login data")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// TODO token deprecation probably should be done in transaction
	oldToken, err := a.tokens.GetNotExpiredTokenByToken(request.Token)
	if err != nil {
		a.logger.Error().Err(err).Str("token", request.Token).Msg("Unable to get not expired token")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	expiration := time.Now().Add(30 * time.Minute)
	newToken, err := a.tokens.CreateToken(oldToken.Claims.ID, oldToken.Claims.Email, expiration)
	if err != nil {
		a.logger.Error().Err(err).
			Str("user_id", oldToken.Claims.ID.String()).
			Str("email", oldToken.Claims.Email).
			Msg("Unable to create new token")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = a.tokens.DeprecateToken(oldToken)
	if err != nil {
		a.logger.Error().Err(err).Str("token", oldToken.Token).Msg("Unable to deprecate token")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp := loginResponse{
		Token: newToken.Token,
	}

	a.logger.Info().
		Str("old_token", oldToken.Token).
		Str("new_token", newToken.Token).
		Time("exp", expiration).
		Msg("Token has been refreshed")

	w.WriteHeader(http.StatusAccepted)
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(resp); err != nil {
		a.logger.Error().Err(err).Msg("Encoder error")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
