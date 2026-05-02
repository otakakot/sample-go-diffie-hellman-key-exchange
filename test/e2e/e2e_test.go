package e2e_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/otakakot/sample-go-diffie-hellman-key-exchange/internal/key"
	"github.com/otakakot/sample-go-diffie-hellman-key-exchange/pkg/api"
)

func TestE2e(t *testing.T) {
	t.Parallel()

	endpoint := os.Getenv("ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	cli, err := api.NewClient(endpoint)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	t.Run("Submit Passowrd", func(t *testing.T) {
		privateKey, err := key.GenerateECDH()
		if err != nil {
			t.Fatal(err)
		}

		encodedPublicKey, err := key.EncodeECDHPublicKey(privateKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		sessionRes, err := cli.CreateSession(ctx, &api.CreateSessionRequestSchema{
			EncodedPublicKey: encodedPublicKey,
		})
		if err != nil {
			t.Fatal(err)
		}

		switch sessionRes.(type) {
		case *api.CreateSessionResponseSchema:
		default:
			t.Fatalf("unexpected response type: %T", sessionRes)
		}

		res := sessionRes.(*api.CreateSessionResponseSchema)

		publicKey, err := key.DecodeECDHPublicKey(res.EncodedPublicKey)
		if err != nil {
			t.Fatal(err)
		}

		commonKey, err := privateKey.ECDH(publicKey)
		if err != nil {
			t.Fatal(err)
		}

		encrypted, err := key.Encrypt(commonKey, []byte(uuid.NewString()))
		if err != nil {
			t.Fatal(err)
		}

		passwordRes, err := cli.SubmitPassword(ctx, &api.SubmitPasswordRequestSchema{
			Session:           res.Session,
			EncryptedPassword: encrypted,
		})
		if err != nil {
			t.Fatal(err)
		}

		switch res := passwordRes.(type) {
		case *api.SubmitPasswordCreated:
			t.Log("success")
		case *api.ErrorResponseSchema:
			t.Fatalf("error response: %+v", res.Message)
		default:
			t.Fatalf("unexpected response type: %T", passwordRes)
		}
	})
}
