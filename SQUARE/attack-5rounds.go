package main

import(
	"fmt"
	"encoding/hex"
	"bytes"

	"math/rand"
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
func setup(key []byte, rest int) [][]byte {

	// non-active byte
	if rest == -1 {
		rest = rand.Intn(256)
	}

	// creating a delta set
	delta_set := make([][]byte, 256)
	for ii := 0; ii < 256; ii++ {
		delta_set[ii] = bytes.Repeat([]byte{byte(rest)}, 16)
		delta_set[ii][0] = byte(ii)
	}

	// encrypt everything!
	encrypted_delta_set := make([][]byte, 256)
	for ii := 0; ii < 256; ii++ {
		encrypted_delta_set[ii] = EncryptWithRounds(5, key, delta_set[ii])
	}

	return encrypted_delta_set
}

// check a key guess by XORing every byte of every position until != 0
// takes `valid_keys` to keep track of invalid/valid guesses
// takes `key_guess` to keep track as well
// takes `set` the reversed bytes from the delta-set after the key guess

var valid_keys []uint64

func checkKeyGuess(key_guess uint64, byte_set []byte) bool {

	// xor everything in
	var xor_result byte = 0
	for ii := 0; ii < 256; ii++ {
		xor_result ^= byte_set[ii]
	}

	// good guess!
	if xor_result == 0 {
		return true
	}

	return false
}

// check if we have found the key, otherwise we need to test with another delta-set
func checkFinished(valid_keys []uint64) bool {

	// count how many valid keys there are
	if number_true := len(valid_keys); number_true == 0 {
		panic("no valid keys?")
	} else if number_true == 1 {
		return true
	} else {
		return false
	}

}

//
func reverseState(key_guess []byte, encrypted_delta_state [][]byte, byte_idx int) []byte {

	var col_set [256][4]byte
	var byte_set [256]byte

	for set := 0; set < 256; set ++ {
		// reverse last addKeyRound
		copy(col_set[set][0:4], key_guess[0:4])
		col_set[set][0] ^= encrypted_delta_state[set][byte_idx * 4]
		col_set[set][1] ^= encrypted_delta_state[set][(byte_idx * 4 + 13) % 16]
		col_set[set][2] ^= encrypted_delta_state[set][(byte_idx * 4 + 10) % 16]
		col_set[set][3] ^= encrypted_delta_state[set][(byte_idx * 4 + 7) % 16]

		// reverse last ShiftRows // nothing

		// reverse last SubBytes
		for byte_pos := uint(0); byte_pos < 4; byte_pos ++ {
			col_set[set][byte_pos] = sbox1[(col_set[set][byte_pos] >> 4) * 16 + (col_set[set][byte_pos] & 0x0f)]
		}

		// MixColumnInv
		//byte_set[set] = Mult(0x0e, col_set[set][0]) ^ Mult(0x0b, col_set[set][1]) ^ Mult(0x0d, col_set[set][2]) ^ Mult(0x09, col_set[set][3])
		// TODO: this is different according to the column we're reversing, this is only valid for the first column
		// TODO: actually ^ I think this if false, each line has the same. Since we always analyze something on the same line (differently column) we're good.
		byte_set[set] = ltm14[col_set[set][0]] ^ ltm11[col_set[set][1]] ^ ltm13[col_set[set][2]] ^ ltm9[col_set[set][3]]

		// reverse AddKeyRound with the key trick
		byte_set[set] ^= key_guess[4]

		// reverse ShiftRows // do nothing

		// reverse last SubBytes
		byte_set[set] = sbox1[(byte_set[set] >> 4) * 16 + (byte_set[set] & 0x0f)]
	}

	return byte_set[:]
}

//
func reverseAndCheck(key_guess uint64, encrypted_delta_set [][]byte, byte_idx int) bool {

	// reverse the set with that key and only for a certain byte up until the AddRoundKey
	test_set := reverseState(uint64ToByte(key_guess), encrypted_delta_set, byte_idx)

	// check if the byte is balanced in all the set and keep track in `valid_keys`
	return checkKeyGuess(key_guess, test_set)
}

//
// helper
//

// [44, 33, 22, 11, 00] -> 0x--------0011223344
func byteToUint64(array []byte) uint64 {
	var result uint64
	for index, val := range array {
		result ^= uint64(val) << (uint(index) * 8)
	}
	return result
}

// 0x--------0011223344 -> [44, 33, 22, 11, 00]
func uint64ToByte(thing uint64) []byte {
	var result = make([]byte, 0)
	for ii := uint(0); ii < 5; ii++ {
		result = append(result, byte((thing >> (ii * 8)) & 0xff))
	}
	return result
}

//
func main(){
	// randomness
	rand.Seed(42)

	// key to find
	key_str := "2b7e151628aed2a6abf7158809cf4f3c"
	key, _ := hex.DecodeString(key_str)

	//
	// ATTACK ON 5 ROUND
	//
	
	key_found := make([]byte, 0)

	// guess byte by byte
	for byte_idx := 0; byte_idx < 4; byte_idx ++ {

		// do this until key is found
		valid_keys := make([]uint64, 0)

		// do this until we don't have anymore key guess
		tries := 1
		
		for {
			fmt.Println("try", tries)
			encrypted_delta_set := setup(key, -1)
			encrypted_delta_set2 := setup(key, -1)
			encrypted_delta_set3 := setup(key, -1)

			// first try
			if len(valid_keys) == 0 {
				for key_guess := uint64(0); key_guess < (2 << 39); key_guess++ {

					// timer display (Debug)
					if key_guess % 100000 == 0 {
						fmt.Println(float64(key_guess) / (2<<39))
						fmt.Println("current list", valid_keys)
					}

					// valid key for 3 different tests
					if reverseAndCheck(key_guess, encrypted_delta_set, byte_idx) {
						if reverseAndCheck(key_guess, encrypted_delta_set2, byte_idx) {
							if reverseAndCheck(key_guess, encrypted_delta_set3, byte_idx) {
								valid_keys = append(valid_keys, key_guess)
							}
						}
					}

				}
				// second, third, ... tries
			} else {

				next_try := make([]uint64, 0)

				for _, key_guess := range valid_keys {
					// if valid, add to next try list
					if reverseAndCheck(key_guess, encrypted_delta_set, byte_idx) {
						next_try = append(next_try, key_guess)
					}
				}

				// current_list <- next_list
				valid_keys = next_try
					
			}

			// debug
			fmt.Println("we've tested all the combinations")

			// check if we found the key
			if checkFinished(valid_keys) {
				key_byte_found := valid_keys[0]
				fmt.Println("found key", key_byte_found," after only ", tries, " tries")

				result := uint64ToByte(key_byte_found)
				key_found = append(key_found, result[:4]...)
				fmt.Println("^ this is false, since the bytes are not ordered correctly :)")
				break // the infinite loop
			} else {
				tries ++
			}

			// end of infinite loop
		}

	}

	// just to make sure
	subKeys := keySchedule(key)

	fmt.Println("key byte to find:", subKeys[4*16: 5*16])
	fmt.Println("key byte found:", key_found)
	
}
	
