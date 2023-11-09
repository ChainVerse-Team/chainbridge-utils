package hash

import (
	"encoding/base64"

	"golang.org/x/crypto/sha3"
)

var salt = []byte("3.14159265358979323846")
const times = 10_000_000

// Combine password and salt then hash them using the SHA-512
// hashing algorithm and then return the hashed password
// as a base64 encoded string
func HashPassword(password string) (string, error) {
	// Convert password string to byte slice
	var passwordBytes = []byte(password)

	// Create sha-512 hasher
	var keccak256Hasher = sha3.NewLegacyKeccak256()

	// Append salt to password
	passwordBytes = append(passwordBytes, salt...)

	// Write password bytes to the hasher
	_, err := keccak256Hasher.Write(passwordBytes)
	if err != nil {
		return "", err
	}

	// Get the SHA-512 hashed password
	var hashedPasswordBytes = keccak256Hasher.Sum(nil)

	// Convert the hashed password to a base64 encoded string
	var base64EncodedPasswordHash = base64.URLEncoding.EncodeToString(hashedPasswordBytes)

	return base64EncodedPasswordHash, nil
}


func HashPasswordIteratively(password string) []byte {
	for i := 1; i < times; i++ {
		password, _ = HashPassword(password)
	}
	return []byte(password)
}