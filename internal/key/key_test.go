package key_test

import (
	"bytes"
	"testing"

	"github.com/otakakot/sample-go-diffie-hellman-key-exchange/internal/key"
)

func TestDiffieHellmanKeyExchange(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{
			name:   "Diffie-Hellman Key Exchange",
			target: "pass",
		},
		{
			name:   "Diffie-Hellman Key Exchange",
			target: "password",
		},
		{
			name:   "Diffie-Hellman Key Exchange",
			target: "passwordpass",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKeyA, err := key.GenerateECDH()
			if err != nil {
				t.Fatal(err)
			}

			privKeyB, err := key.GenerateECDH()
			if err != nil {
				t.Fatal(err)
			}

			commonKeyA, err := privKeyA.ECDH(privKeyB.PublicKey())
			if err != nil {
				t.Fatal(err)
			}

			commonKeyB, err := privKeyB.ECDH(privKeyA.PublicKey())
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(commonKeyA, commonKeyB) {
				t.Fatalf("commonKeyA and commonKeyB are not equal")
			}

			encrypted, err := key.Encrypt(commonKeyA, []byte(tt.target))
			if err != nil {
				t.Fatal(err)
			}

			decrypted, err := key.Decrypt(commonKeyB, encrypted)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal([]byte(tt.target), decrypted) {
				t.Fatalf("decrypted is not equal to target. decrypted: %s, target: %s", decrypted, tt.target)
			}
		})
	}
}
