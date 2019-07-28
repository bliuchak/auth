package main

import (
	"github.com/ibliuchak/auth/internal/tokens"

	"github.com/ibliuchak/auth/internal/platform/storage"
	"github.com/ibliuchak/auth/internal/users"

	"github.com/ibliuchak/auth/cmd/httpd/server"
	"github.com/ibliuchak/auth/cmd/httpd/server/handler"

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

	home := handler.NewHome(&logger)

	usersModel := users.NewUsers(st)
	user := handler.NewUsers(&logger, *usersModel)

	tokensModel := tokens.NewTokens(jwtKey, st)
	auth := handler.NewAuth(logger, *usersModel, *tokensModel)

	middleware := handler.NewMiddleware(jwtKey, logger)

	server.NewServer(
		logger,
		server.NewRouter(home, user, auth, middleware).Init(),
		port,
	).Run()
}
