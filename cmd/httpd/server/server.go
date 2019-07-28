package server

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-chi/chi"

	"github.com/rs/zerolog"
)

type Server struct {
	logger zerolog.Logger
	router *chi.Mux
	port   string
}

func NewServer(logger zerolog.Logger, router *chi.Mux, port string) *Server {
	return &Server{logger: logger, router: router, port: port}
}

func (s *Server) Run() {
	s.logger.Info().Str("port", s.port).Msg("Start http server")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	shutdown := make(chan error, 1)

	server := http.Server{
		Addr:    net.JoinHostPort("", s.port),
		Handler: s.router,
	}

	go func() {
		err := server.ListenAndServe()
		shutdown <- err
	}()

	select {
	case killSignal := <-interrupt:
		switch killSignal {
		case os.Interrupt:
			s.logger.Info().Msg("Got SIGINT...")
		case syscall.SIGTERM:
			s.logger.Info().Msg("Got SIGTERM...")
		}
	case <-shutdown:
		s.logger.Info().Msg("Got an error...")
	}

	s.logger.Info().Msg("The service is stopping...")
	err := server.Shutdown(context.Background())
	if err != nil {
		s.logger.Warn().Err(err).Msg("Got an error during service shutdown")
	}
	s.logger.Info().Msg("The service is stopped")
}
