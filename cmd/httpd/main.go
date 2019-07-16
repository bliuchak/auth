package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/ibliuchak/auth/internal/tokens"

	"github.com/ibliuchak/auth/internal/platform/storage"
	"github.com/ibliuchak/auth/internal/users"

	"github.com/ibliuchak/auth/cmd/httpd/handlers"
	"github.com/ibliuchak/auth/cmd/httpd/server"

	"github.com/go-chi/chi"
	"github.com/rs/zerolog"
)

func main() {
	port := "3001"
	clusterAddress := "couchbase://auth_storage_1"
	clusterUsername := "admin"
	clusterPassword := "testtest"
	jwtKey := []byte("my_secret_key")

	logger := zerolog.New(zerolog.NewConsoleWriter()).With().Timestamp().Logger()

	st, err := storage.NewCouchbaseStorage(clusterAddress, clusterUsername, clusterPassword)
	if err != nil {
		logger.Error().Err(err).Str("address", clusterAddress).Msg("can't init storage")
	}

	hh := handlers.NewHome(&logger)

	usersModel := users.NewUsers(st)
	uh := handlers.NewUsers(&logger, *usersModel)

	tokensModel := tokens.NewTokens(jwtKey, st)
	ah := handlers.NewAuth(logger, *usersModel, *tokensModel)

	m := server.NewMiddleware(jwtKey, logger)

	// TODO: separate router
	r := chi.NewRouter()

	r.Get("/", hh.GetHome)
	r.Put("/user", uh.CreateUser)
	r.Post("/login", ah.Login)
	r.Post("/refresh", ah.Refresh)
	r.With(m.JWTValidation).Get("/user/{userID}", uh.GetUserByID)

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
