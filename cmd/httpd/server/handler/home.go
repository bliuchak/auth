package handler

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

type Home struct {
	logger *zerolog.Logger
}

func NewHome(logger *zerolog.Logger) *Home {
	return &Home{logger: logger}
}

func (h *Home) GetHome(w http.ResponseWriter, r *http.Request) {
	h.logger.Info().Msg("status triggered")
	fmt.Fprint(w, "i'm auth service, hello")
}
