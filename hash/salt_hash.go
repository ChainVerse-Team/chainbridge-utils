package hash

import (
	"errors"

	"github.com/ChainSafe/chainbridge-utils/bcrypt"
	"golang.org/x/crypto/sha3"
)

var (
	salt = []byte("3.14159265358979323846")
	lengthOfSalt = len(salt)
)
const times = 2_000 // target 2 minutes

var (
	ErrIncorrectLength  = errors.New("byte slices must have the same length")
)

// Combine password and salt then hash them using the keccak-256
// hashing algorithm and then return the hashed password
// as a base64 encoded string
func hashPassword(password []byte) ([]byte, error) {
	// Create keccak-256 hasher
	var keccak256Hasher = sha3.New256()

	// Write password bytes to the hasher
	_, err := keccak256Hasher.Write(password)
    for i:= 0; i < len(password); i++ {
		password[i] = 0;
	}
	if err != nil {
        keccak256Hasher.Reset()
        keccak256Hasher = nil
		return nil, err
	}
    
	
	var hashedPasswordBytes = keccak256Hasher.Sum(nil)
    keccak256Hasher.Reset()
    keccak256Hasher = nil
	return hashedPasswordBytes, nil
}


// HashPasswordIteratively is a function that iteratively hashes a password for enhanced security.
// It takes the initial password as a string and iteratively applies a hashing algorithm to it
// a specified number of times.
// The function returns the final hashed password as a byte slice, the salt used during hashing
// as a byte slice, and any error encountered during the process.
func HashPasswordIteratively(password []byte) ([]byte, []byte, error) {
    // Hash the initial password using the hashPassword function
    hashedPwd, err := hashPassword(password)
    for i := 0; i < len(password); i++ {
		password[i] = 0
	}
    if err != nil {
        return nil, nil, err
    }
	

    // Iteratively apply the bcrypt hashing algorithm a specified number of times
    for i := 0; i < times; i++ {
        // Apply bcrypt hashing to the previously hashed password
        hashedPwd, err = bcrypt.Bcrypt(hashedPwd, bcrypt.DefaultCost, salt)
        if err != nil {
            for i := 0; i < len(hashedPwd); i++ {
                hashedPwd[i] = 0
            }
            for i := 0; i < len(salt); i++ {
                salt[i] = 0
            }
            return nil, nil, err
        }

        // XOR the first 22 bytes of the hashed password with the salt
        salt, err = xorBytes(hashedPwd[:lengthOfSalt], salt)
        if err != nil {
            for i := 0; i < len(hashedPwd); i++ {
                hashedPwd[i] = 0
            }
            for i := 0; i < len(salt); i++ {
                salt[i] = 0
            }
            return nil, nil, err
        }
    }

    // Return the final hashed password, the salt, and no error
    return hashedPwd, salt, nil
}


// xorBytes takes two byte slices a and b as input and performs a bitwise XOR operation
// on the corresponding elements of the slices. It returns the result of the XOR operation
// as a new byte slice. If the input slices have different lengths, it returns an error.
func xorBytes(a, b []byte) ([]byte, error) {
    // Check if the lengths of slices a and b are different
    if len(a) != len(b) {
        // If the lengths are different, return an error
        return nil, ErrIncorrectLength
    }

    // Create a new byte slice with the same length as input slice a
    result := make([]byte, len(a))

    // Perform the XOR operation on each pair of corresponding elements
    for i := range a {
        result[i] = a[i] ^ b[i]
    }

    // Return the result of the XOR operation and no error
    return result, nil
}