package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/otakakot/sample-go-diffie-hellman-key-exchange/internal/key"
	"github.com/otakakot/sample-go-diffie-hellman-key-exchange/pkg/api"
)

func main() {
	hdl, err := api.NewServer(&Handler{
		sesison: map[string]key.CommonKey{},
	})
	if err != nil {
		panic(err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           hdl,
		ReadHeaderTimeout: 30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	defer stop()

	go func() {
		slog.Info("start server listen")

		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-ctx.Done()

	slog.Info("start server shutdown")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err)
	}

	slog.Info("done server shutdown")
}

var _ api.Handler = (*Handler)(nil)

type Handler struct {
	sesison map[string]key.CommonKey
}

// CreateSession implements api.Handler.
func (hdl *Handler) CreateSession(ctx context.Context, req *api.CreateSessionRequestSchema) (api.CreateSessionRes, error) {
	session := uuid.NewString()

	publicKey, err := key.DecodeECDHPublicKey(req.EncodedPublicKey)
	if err != nil {
		return &api.ErrorResponseSchema{
			Message: err.Error(),
		}, nil
	}

	privateKey, err := key.GenerateECDH()
	if err != nil {
		return &api.ErrorResponseSchema{
			Message: err.Error(),
		}, nil
	}

	commonKey, err := privateKey.ECDH(publicKey)
	if err != nil {
		return &api.ErrorResponseSchema{
			Message: err.Error(),
		}, nil
	}

	hdl.sesison[session] = commonKey

	enc, err := key.EncodeECDHPublicKey(privateKey.PublicKey())
	if err != nil {
		return &api.ErrorResponseSchema{
			Message: err.Error(),
		}, nil
	}

	return &api.CreateSessionResponseSchema{
		Session:          session,
		EncodedPublicKey: enc,
	}, nil
}

// SubmitPassword implements api.Handler.
func (hdl *Handler) SubmitPassword(ctx context.Context, req *api.SubmitPasswordRequestSchema) (api.SubmitPasswordRes, error) {
	slog.Info(fmt.Sprintf("encoded password: %s", req.EncryptedPassword))

	commonKey, ok := hdl.sesison[req.Session]
	if !ok {
		return &api.ErrorResponseSchema{
			Message: "session not found",
		}, nil
	}

	decrypted, err := key.Decrypt(commonKey, req.EncryptedPassword)
	if err != nil {
		return &api.ErrorResponseSchema{
			Message: err.Error(),
		}, nil
	}

	slog.Info(fmt.Sprintf("decrypted password: %s", string(decrypted)))

	return &api.SubmitPasswordCreated{}, nil
}
