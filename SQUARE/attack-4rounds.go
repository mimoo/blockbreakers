package main

import(
	"fmt"
	"encoding/hex"
	"bytes"
)

// encryption
func EncryptWithRounds(rounds int, key []byte, plaintext []byte) []byte {
	// copy the state in a new state
	state := make([]byte, len(plaintext))
	copy(state, plaintext)

	// create the subKeys
	subKeys := keySchedule(key)

	if verbose {
		fmt.Println("Subkeys:")
		for id, ii := range(subKeys) {
			if id % 16 == 0 {
				fmt.Println()
			}
			fmt.Printf("%02x", ii)
		}
		fmt.Println("\n")
	}
	
	// pre-whitening
	AddRoundKey(state, subKeys, 0)

	// rounds 1 to n-1
	var round int
	for round = 1; round < rounds; round ++ {
		SubBytes(state, true)
		ShiftRows(state, true)
		MixColumns(state, true)
		AddRoundKey(state, subKeys, round)
	}

	// last round
	SubBytes(state, true)
	ShiftRows(state, true)
	AddRoundKey(state, subKeys, round)

	return state
}

//
// ATTACK
//

// Setup creates a delta set and encrypt it
// takes `rest` which is the byte used to fill the non-active bytes
// takes `key` to encrypt each item of the delta set
func setup(key []byte, rest byte) [][]byte {
	// creating a delta set
	delta_set := make([][]byte, 256)
	for ii := 0; ii < 256; ii++ {
		delta_set[ii] = bytes.Repeat([]byte{rest}, 16)
		delta_set[ii][0] = byte(ii)
	}

	// encrypt everything!
	encrypted_delta_set := make([][]byte, 256)
	for ii := 0; ii < 256; ii++ {
		encrypted_delta_set[ii] = EncryptWithRounds(4, key, delta_set[ii])
	}

	return encrypted_delta_set
}

// check a key guess by XORing every byte of every position until != 0
// takes `valid_keys` to keep track of invalid/valid guesses
// takes `key_guess` to keep track as well
// takes `set` the reversed bytes from the delta-set after the key guess
func checkKeyGuess(valid_keys map[int]bool, key_guess int, set []byte) {

	// xor everything in
	var xor_result byte = 0
	for ii := 0; ii < 256; ii++ {
		xor_result ^= set[ii]
	}

	// not good
	if xor_result != 0 {
		valid_keys[key_guess] = false
	} else if _, ok := valid_keys[key_guess]; !ok {	// good, only if not marked before
		valid_keys[key_guess] = true
	}

}

// check if we have found the key, otherwise we need to test with another delta-set
func checkFinished(valid_keys map[int]bool) (byte, bool) {

	number_true := 0
	key_byte_found := 0

	// count how many valid keys there are
	for idx, val := range valid_keys {
		if val {
			number_true ++
			key_byte_found = idx
		}
	}
	// if only one key is, we can stop
	if number_true == 1 {
		return byte(key_byte_found), true
	}

	return 0, false
}

//
func reverseLastRound(key_guess byte, encrypted_delta_state [][]byte, byte_idx int) []byte {

	var byte_set [256]byte

	// reverse last addKeyRound
	for set := 0; set < 256; set ++ {
		byte_set[set] = key_guess ^ encrypted_delta_state[set][byte_idx]
	}

	// reverse last ShiftRows 	// nothing to do

	// reverse last SubBytes
	for set:= 0; set < 256; set ++ {
		row := byte_set[set] >> 4
		col := byte_set[set] & 0x0f
		byte_set[set] = sbox1[row * 16 + col]
	}

	//
	return byte_set[:]
}

//
func reverseAndCheck(key_guess int, encrypted_delta_set [][]byte, byte_idx int, valid_keys map[int]bool){
	// reverse the set with that key and only for a certain byte
	test_set := reverseLastRound(byte(key_guess), encrypted_delta_set, byte_idx)
	// check if the byte is balanced in all the set and keep track in `valid_keys`
	checkKeyGuess(valid_keys, key_guess, test_set)
}

//
func main(){
	// key to find
	key_str := "2b7e151628aed2a6abf7158809cf4f3c"
	key, _ := hex.DecodeString(key_str)

	//
	// ATTACK ON 4 ROUND
	//
	
	key_found := make([]byte, 0)

	// guess byte by byte
	for byte_idx := 0; byte_idx < 16; byte_idx ++ {

		// do this until key is found
		valid_keys := make(map[int]bool, 256)

		// we might need several delta-set to find the byte key
		for rest := 0; rest < 256; rest++ {

			// create encrypted data set
			encrypted_delta_set := setup(key, byte(rest))
			
			// try key guesses for that byte
			if len(valid_keys) == 0 { // first time
				for key_guess := 0; key_guess < 256; key_guess++ {
					reverseAndCheck(key_guess, encrypted_delta_set, byte_idx, valid_keys)
				}
			} else { // first time has many valid guess instead of one valid guess
				for key_guess, ok := range valid_keys {
					if ok {
						reverseAndCheck(key_guess, encrypted_delta_set, byte_idx, valid_keys)
					}
				}
			}

			// check if we found the key
			if key_byte_found, ok := checkFinished(valid_keys); ok {
				fmt.Println("found key", key_byte_found," after only ", rest + 1, " tries")
				key_found = append(key_found, key_byte_found)
				break
			}

		}

	}

	// just to make sure
	subKeys := keySchedule(key)

	fmt.Println("key byte to find:", subKeys[4*16: 5*16])
	fmt.Println("key byte found:", key_found)
	
}
	
