package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"

	"github.com/google/uuid"

	"gopkg.in/couchbase/gocb.v1"

	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
)

type User struct {
	ID       uuid.UUID
	Email    string
	Password string
}

type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
}

type Token struct {
	Token  string `json:"token"`
	Claims Claims `json:"claims"`
}

type Claims struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	jwt.StandardClaims
}

type ValidateTokenRequest struct {
	Token string `json:"token"`
}

var jwtKey = []byte("my_secret_key")

func main() {
	port := "3001"
	clusterAddress := "couchbase://auth_storage_1"
	clusterUsername := "admin"
	clusterPassword := "testtest"

	logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()

	cluster, err := gocb.Connect(clusterAddress)
	if err != nil {
		logger.Error().Err(err).Str("address", clusterAddress).Msg("Cluster connection error")
	}

	if err = cluster.Authenticate(gocb.PasswordAuthenticator{
		Username: clusterUsername,
		Password: clusterPassword,
	}); err != nil {
		logger.Error().Err(err).Msg("Cluster auth error")
	}

	// TODO: create necessary buckets on app start
	//err = cluster.Manager("admin", "testtest").InsertBucket(&gocb.BucketSettings{
	//	Name:  "users",
	//	Quota: 100,
	//})
	//if err != nil {
	//	panic(err)
	//}
	//err = cluster.Manager(clusterUsername, clusterPassword).InsertBucket(&gocb.BucketSettings{
	//	Name:  "tokens",
	//	Quota: 100,
	//})
	//if err != nil {
	//	panic(err)
	//}

	users, err := cluster.OpenBucket("users", "")
	if err != nil {
		logger.Error().Err(err).Str("name", "users").Msg("Unable open bucket")
	}

	if err := users.Manager(clusterUsername, clusterPassword).CreatePrimaryIndex("", true, false); err != nil {
		logger.Error().Err(err).Str("name", "users").Msg("Can't create primary index")
	}

	tokens, err := cluster.OpenBucket("tokens", "")
	if err != nil {
		logger.Error().Err(err).Str("name", "tokens").Msg("Unable open bucket")
	}

	if err := tokens.Manager(clusterUsername, clusterPassword).CreatePrimaryIndex("", true, false); err != nil {
		logger.Error().Err(err).Str("name", "tokens").Msg("Can't create primary index")
	}

	// TODO: separate router
	r := chi.NewRouter()

	// basic app info
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		logger.Info().Msg("status triggered")
		fmt.Fprint(w, "i'm auth service, hello")
	})

	// creates new user
	r.Put("/user", func(w http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		var request CreateUserRequest
		err := decoder.Decode(&request)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decode user data")
		}

		userID := uuid.New()
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
		if err != nil {
			logger.Error().Err(err).Str("email", request.Email).Msg("Unable to generate hash for a password")
		}

		user := User{
			ID:       userID,
			Email:    request.Email,
			Password: string(hashedPassword),
		}

		cas, err := users.Upsert(userID.String(), user, 0)
		if err != nil {
			logger.Error().Err(err).Msg("Error happened during user upsertion")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		logger.Info().Str("email", user.Email).Interface("cas", cas).Msg("New user created")
		w.WriteHeader(http.StatusCreated)
	})

	// user auth
	r.Post("/login", func(w http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		var request LoginRequest
		err := decoder.Decode(&request)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decode login data")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		query := gocb.NewN1qlQuery("select `ID`,`Email`,`Password` from `users` where `Email`=$email")

		params := make(map[string]interface{})
		params["email"] = request.Email

		rows, err := users.ExecuteN1qlQuery(query, params)
		if err != nil {
			logger.Error().Err(err).Str("email", request.Email).Msg("Can't get user")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var row User
		var tokenString string
		for rows.Next(&row) {
			err = bcrypt.CompareHashAndPassword([]byte(row.Password), []byte(request.Password))
			if err != nil {
				logger.Error().Err(err).Str("email", request.Email).Msg("Bad password")
				w.WriteHeader(http.StatusForbidden)
				return
			}

			logger.Info().Str("email", row.Email).Msg("Successful login")
		}

		expirationTime := time.Now().Add(30 * time.Minute)
		claims := &Claims{
			ID:    row.ID,
			Email: row.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err = token.SignedString(jwtKey)
		if err != nil {
			logger.Error().Err(err).Msg("Error while SignedString")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		tokenData := Token{
			Token: tokenString,
			Claims: Claims{
				ID:    row.ID,
				Email: row.Email,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
				},
			},
		}

		_, err = tokens.Upsert(tokenString, tokenData, 0)
		if err != nil {
			logger.Error().Err(err).Msg("Error happened during token upsertion")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resp := LoginResponse{
			Token: tokenString,
		}

		logger.Info().Str("token", tokenString).Time("exp", expirationTime).Msg("New token issued")

		w.WriteHeader(http.StatusAccepted)
		encoder := json.NewEncoder(w)
		if err := encoder.Encode(resp); err != nil {
			logger.Error().Err(err).Msg("Encoder error")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})

	// jwt token validation
	r.Post("/refresh", func(w http.ResponseWriter, req *http.Request) {
		decoder := json.NewDecoder(req.Body)
		var request ValidateTokenRequest
		err := decoder.Decode(&request)
		if err != nil {
			logger.Error().Err(err).Msg("Unable to decode login data")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		query := gocb.NewN1qlQuery("select claims, token from tokens where claims.exp > $now and token = $token")

		params := make(map[string]interface{})
		params["token"] = request.Token
		params["now"] = time.Now().Unix()

		rows, err := tokens.ExecuteN1qlQuery(query, params)
		if err != nil {
			logger.Error().Err(err).Str("token", request.Token).Msg("Can't get token")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		rows.Close()

		if rows.Metrics().ResultCount == 0 {
			logger.Error().Err(err).Str("token", request.Token).Msg("Token not found")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var row Token
		for rows.Next(&row) {
			logger.Info().Str("token", row.Token).Msg("Successful get token")
			break
		}

		expirationTime := time.Now().Add(30 * time.Minute)
		claims := &Claims{
			ID:    row.Claims.ID,
			Email: row.Claims.Email,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		var tokenString string
		tokenString, err = token.SignedString(jwtKey)
		if err != nil {
			logger.Error().Err(err).Msg("Error while SignedString")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		tokenData := Token{
			Token: tokenString,
			Claims: Claims{
				ID:    row.Claims.ID,
				Email: row.Claims.Email,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: expirationTime.Unix(),
				},
			},
		}

		_, err = tokens.Upsert(tokenString, tokenData, 0)
		if err != nil {
			logger.Error().Err(err).Msg("Error happened during token upsertion")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// after new token is issued we need instantly expire previous one
		row.Claims.ExpiresAt = 1
		_, err = tokens.Upsert(row.Token, row, 0)
		if err != nil {
			logger.Error().Err(err).Msg("Error happened during token upsertion")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		logger.Info().Str("token", row.Token).Msg("Old token is expired")

		resp := LoginResponse{
			Token: tokenString,
		}

		logger.Info().Str("token", tokenString).Time("exp", expirationTime).Msg("New token issued")

		w.WriteHeader(http.StatusAccepted)
		encoder := json.NewEncoder(w)
		if err := encoder.Encode(resp); err != nil {
			logger.Error().Err(err).Msg("Encoder error")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	})

	logger.Info().Str("port", port).Msg("Start http server")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	shutdown := make(chan error, 1)

	server := http.Server{
		Addr:    net.JoinHostPort("", port),
		Handler: r,
	}

	go func() {
		err := server.ListenAndServe()
		shutdown <- err
	}()

	select {
	case killSignal := <-interrupt:
		switch killSignal {
		case os.Interrupt:
			logger.Info().Msg("Got SIGINT...")
		case syscall.SIGTERM:
			logger.Info().Msg("Got SIGTERM...")
		}
	case <-shutdown:
		logger.Info().Msg("Got an error...")
	}

	logger.Info().Msg("The service is stopping...")
	err = server.Shutdown(context.Background())
	if err != nil {
		logger.Warn().Err(err).Msg("Got an error during service shutdown")
	}
	logger.Info().Msg("The service is stopped")
}
