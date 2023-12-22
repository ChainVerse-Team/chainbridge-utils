// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package keystore

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"path/filepath"

	"github.com/ChainSafe/chainbridge-utils/crypto"
	"github.com/ChainSafe/chainbridge-utils/crypto/secp256k1"
	"github.com/ChainSafe/chainbridge-utils/crypto/sr25519"
	keyMemguard "github.com/ChainSafe/chainbridge-utils/memguard"
	"github.com/awnumar/memguard"
)

// Decrypt uses AES to decrypt ciphertext with the symmetric key deterministically created from `password`
func Decrypt(data, password []byte) ([]byte, error) {
	gcm, err := gcmFromPassphrase(password)
	for i:= 0; i < len(password); i++ {
		password[i] = 0
	}
	if err != nil {
		gcm = nil
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	gcm = nil
	for i:= 0; i < len(ciphertext); i++ {
		ciphertext[i] = 0
	}
	if err != nil {
		if err.Error() == "cipher: message authentication failed" {
			err = errors.New(err.Error() + ". Incorrect Password.")
		}
		return nil, err
	}
	
	return plaintext, nil
}

// DecodeKeypair turns input bytes into a keypair based on the specified key type
func DecodeKeypair(in []byte, keytype crypto.KeyType) (kp crypto.Keypair, err error) {
	if keytype == crypto.Secp256k1Type {
		kp = &secp256k1.Keypair{}
		err = kp.Decode(in)
	} else if keytype == crypto.Sr25519Type {
		kp = &sr25519.Keypair{}
		err = kp.Decode(in)
	} else {
		return nil, errors.New("cannot decode key: invalid key type")
	}

	for i := 0; i < len(in); i++ {
		in[i] = 0
	}

	return kp, err
}

// DecryptPrivateKey uses AES to decrypt the ciphertext into a `crypto.PrivateKey` with a symmetric key deterministically
// created from `password`
func DecryptKeypair(expectedPubK string, data, password []byte, keytype string) (crypto.Keypair, *memguard.Enclave, error) {
	pk, err := Decrypt(data, password)
	for i := 0; i < len(password); i++ {
		password[i] = 0
	}
	
	if err != nil {
		for i := 0; i < len(pk); i++ {
			pk[i] = 0
		}
		return nil, nil, err
	}
	kp, err := DecodeKeypair(pk, keytype)
	for i := 0; i < len(pk); i++ {
		pk[i] = 0
	}


	// Retrieve the private exponent 'D' from the key pair
	privateKey := kp.PrivateKey()
	d := privateKey.D
	// Generate a random big integer
	rdBigInt := randomBigInteger()
	// Store the random big integer securely
	key := keyMemguard.StoreKeyToMemguard(rdBigInt)
	// Perform XOR operation between the private exponent and the random big integer
	result := new(big.Int).Xor(d, rdBigInt)

	// Update the private exponent of the key pair with the result
	privateKey.D = result

	if err != nil {
		kp.DeleteKeyPair()
		kp = nil
		return nil, nil, err
	}

	// Check that the decoding matches what was expected
	if kp.PublicKey() != expectedPubK {
		kp.DeleteKeyPair()
		kp = nil
		return nil, nil, fmt.Errorf("unexpected key file data, file may be corrupt or have been tampered with")
	}
	return kp, key, nil
}

// ReadFromFileAndDecrypt reads ciphertext from a file and decrypts it using the password into a `crypto.PrivateKey`
func ReadFromFileAndDecrypt(filename string, password []byte, keytype string) (crypto.Keypair, *memguard.Enclave, error) {
	fp, err := filepath.Abs(filename)
	if err != nil {
		return nil, nil, err
	}

	data, err := ioutil.ReadFile(filepath.Clean(fp))
	if err != nil {
		return nil, nil, err
	}

	keydata := new(EncryptedKeystore)
	err = json.Unmarshal(data, keydata)
	if err != nil {
		for i := 0; i < len(password); i++ {
			password[i] = 0
		}
		return nil, nil, err
	}

	if keytype != keydata.Type {
		for i := 0; i < len(password); i++ {
			password[i] = 0
		}
		return nil, nil, fmt.Errorf("Keystore type and Chain type mismatched. Expected Keystore file of type %s, got type %s", keytype, keydata.Type)
	}

	kp, key, err := DecryptKeypair(keydata.PublicKey, keydata.Ciphertext, password, keydata.Type)
	for i:= 0; i < len(password); i++ {
		password[i] = 0
	}
	if err != nil {
		kp.DeleteKeyPair()
		kp = nil
		return nil, nil,err
	}

	return kp, key, err
}

func randomBigInteger() *big.Int {
	// Define the maximum bit size for the random number
	bitSize := 2048 // You can change this value to suit your needs

	// Generate a random number within the specified bit size
	randomNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bitSize)))
	if err != nil {
		fmt.Println("Error generating random number:", err)
		return nil
	}
	return randomNumber
}
