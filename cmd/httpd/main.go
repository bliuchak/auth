package main

import (
	"time"

	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/ibliuchak/auth/internal/tokens"

	"github.com/ibliuchak/auth/internal/platform/storage"
	"github.com/ibliuchak/auth/internal/users"

	"github.com/ibliuchak/auth/cmd/httpd/server"
	"github.com/ibliuchak/auth/cmd/httpd/server/handler"

	"github.com/rs/zerolog"
)

var (
	logger = new(zerolog.Logger)

	port   = kingpin.Flag("port", "port to listen").Envar("PORT").String()
	dbHost = kingpin.Flag("dbhost", "database host").Envar("DB_HOST").String()
	dbUser = kingpin.Flag("dbuser", "database user").Envar("DB_USER").String()
	dbPass = kingpin.Flag("dbpass", "database pass").Envar("DB_PASS").String()
	jwtKey = kingpin.Flag("jwtkey", "jwt key").Envar("JWT_KEY").String()
)

func init() {
	zerolog.TimestampFieldName = "logtimestamp"
	zerolog.TimeFieldFormat = time.RFC3339Nano

	*logger = zerolog.New(zerolog.NewConsoleWriter()).Level(zerolog.InfoLevel).With().Timestamp().Logger()
}

func main() {
	kingpin.Parse()

	s, err := storage.NewCouchbaseStorage(*dbHost, *dbUser, *dbPass)
	if err != nil {
		logger.Error().Err(err).Str("address", *dbHost).Msg("can't init storage")
	}

	home := handler.NewHome(logger)

	usersModel := users.NewUsers(s)
	user := handler.NewUsers(logger, *usersModel)

	tokensModel := tokens.NewTokens([]byte(*jwtKey), s)
	auth := handler.NewAuth(*logger, *usersModel, *tokensModel)

	middleware := handler.NewMiddleware([]byte(*jwtKey), *logger)

	server.NewServer(
		*logger,
		server.NewRouter(home, user, auth, middleware).Init(),
		*port,
	).Run()
}
