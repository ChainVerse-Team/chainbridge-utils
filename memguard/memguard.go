package memguard

import (
	"fmt"
	"math/big"
	"os"

	"github.com/awnumar/memguard"
)

func StoreKeyToMemguard(bigNum *big.Int) *memguard.Enclave {
	// Safely terminate in case of an interrupt signal
	memguard.CatchInterrupt()
	// Purge the session when we return
	defer memguard.Purge()
	byteSlice := bigNum.Bytes()
	key := memguard.NewEnclave(byteSlice)
	return key

}

func GetKeyFromMemguard(key *memguard.Enclave) *big.Int {
	// Decrypt the result returned from invert
	keyBuf, err := key.Open()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return nil
	}
	defer keyBuf.Destroy()
	var bigIntNum *big.Int
	bigIntNum.SetBytes(keyBuf.Bytes())
	return bigIntNum
}