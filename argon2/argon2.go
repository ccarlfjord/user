package argon2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"log"
	"time"

	"golang.org/x/crypto/argon2"
)

var DefaultArgon2 = NewDefaultArgon2()

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func NewDefaultArgon2() *Argon2Params {
	// RFC 9106 recommendations
	return &Argon2Params{
		Memory:      64 * 1024, // 64MB
		Iterations:  3,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func NewArgon2WithParams(memory uint32, iterations uint32, parallelism uint8, saltLength uint32, keyLength uint32) *Argon2Params {
	return &Argon2Params{
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		SaltLength:  saltLength,
		KeyLength:   keyLength,
	}
}

func (a *Argon2Params) Hash(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		a.Iterations,
		a.Memory,
		a.Parallelism,
		a.KeyLength,
	)
}

func (a *Argon2Params) Validate(password string, hashedPassword []byte, salt []byte) error {
	start := time.Now()
	defer func() {
		log.Printf("Validate took %v", time.Since(start))
	}()
	h := a.Hash(password, salt)
	if bytes.Equal(h, hashedPassword) {
		return nil
	}
	return errors.New("password does not match")
}

func (a *Argon2Params) GenerateSalt() []byte {
	salt := make([]byte, a.SaltLength)
	rand.Read(salt)
	return salt
}

func HashPassword(password string, salt []byte) []byte {
	return DefaultArgon2.Hash(password, salt)
}

func Validate(password string, hashedPassword []byte, salt []byte) error {
	return DefaultArgon2.Validate(password, hashedPassword, salt)
}

func GenerateSalt() []byte {
	return DefaultArgon2.GenerateSalt()
}
