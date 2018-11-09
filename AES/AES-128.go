package main

import(
	"fmt"
	"encoding/hex"
	"math"
	"bufio"
	"os"
)

// config
var verbose bool = true
var debug = false

// FIPS-197 Figure 7. S-box substitution values in hexadecimal format.
var sbox0 = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// FIPS-197 Figure 14.  Inverse S-box substitution values in hexadecimal format.
var sbox1 = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

//
func SubBytes(state []byte, encryption bool) {

	for byte_pos := 0; byte_pos < 16; byte_pos++ {

		row := state[byte_pos] >> 4
		col := state[byte_pos] & 0x0f
		//fmt.Printf("byte: %02x, row: %d, col: %d\n", state[byte_pos], row, col)

		if encryption {
			state[byte_pos] = sbox0[row * 16 + col]
		} else {
			state[byte_pos] = sbox1[row * 16 + col]
		}
	}

	if verbose {
		fmt.Println("After SubBytes:")
		printState(state[:])
	}
}

//
func ShiftRows(state []byte, encryption bool) {

	if encryption {
		// 2nd row
		state_temp := state[1]
		state[1] = state[5]
		state[5] = state[9]
		state[9] = state[13]
		state[13] = state_temp

		// 3d row
		state_temp = state[2]
		state_temp2 := state[6]
		state[2] = state[10]
		state[6] = state[14]
		state[10] = state_temp
		state[14] = state_temp2

		// 4th row
		state_temp = state[3]
		state_temp2 = state[7]
		state_temp3 := state[11]
		state[3] = state[15]
		state[7] = state_temp
		state[11] = state_temp2
		state[15] = state_temp3	
	} else {
		// 2nd row
		state_temp := state[1]
		state[1] = state[13]
		state[13] = state[9]
		state[9] = state[5]
		state[5] = state_temp

		// 3d row
		state_temp = state[2]
		state_temp2 := state[6]
		state[6] = state[14]
		state[2] = state[10]
		state[10] = state_temp
		state[14] = state_temp2

		// 4th row
		state_temp = state[15]

		state[15] = state[3]
		state[3] = state[7]
		state[7] = state[11]
		state[11] = state_temp
	}

	if verbose {
		fmt.Println("After ShiftRows:")
		printState(state[:])
	}
}

//
func ModPol(value uint16) byte {
	left := uint8(value >> 8)
	right := uint16(value & math.MaxUint8)

	if left == 0 {
		return uint8(right)
	}

	var result uint16 = 0
	
	for loop := uint8(0); loop < 8; loop ++ {
		if (left >> loop) & 1 == 1 {
			result ^= (27 << loop)
		}
	}

	result ^= right
	return ModPol(result)
}

//
func Mult(left uint8, right byte) byte {

	var result byte = 0

	for shift := uint(0); shift < 4; shift++ {
		if (left >> shift) & 1 == 1 {
			result ^= ModPol(uint16(right) << shift)
		}
	}

	return result

	/*
	if left == 1 {
		return right
	} else if left == 2 {
		return ModPol(uint16(right) << 1)
	} else if left == 3 {
		return right ^ ModPol(uint16(right) << 1)
	} else {
		
	}
*/
}

//
func MixColumns(state []byte, encryption bool) {

	var temp_col [4]byte

	// do the mult
	for col := 0; col < 4; col ++ {
		// create the vector
		temp_col[0] = state[col * 4]
		temp_col[1] = state[col * 4 + 1]
		temp_col[2] = state[col * 4 + 2]
		temp_col[3] = state[col * 4 + 3]

		if encryption {
			state[col * 4] = Mult(2, temp_col[0]) ^ Mult(3, temp_col[1]) ^ Mult(1, temp_col[2]) ^ Mult(1, temp_col[3])
			state[col * 4 + 1] = Mult(1, temp_col[0]) ^ Mult(2, temp_col[1]) ^ Mult(3, temp_col[2]) ^ Mult(1, temp_col[3])
			state[col * 4 + 2] = Mult(1, temp_col[0]) ^ Mult(1, temp_col[1]) ^ Mult(2, temp_col[2]) ^ Mult(3, temp_col[3])
			state[col * 4 + 3] = Mult(3, temp_col[0]) ^ Mult(1, temp_col[1]) ^ Mult(1, temp_col[2]) ^ Mult(2, temp_col[3])
		} else {
			state[col * 4] = Mult(0x0e, temp_col[0]) ^ Mult(0x0b, temp_col[1]) ^ Mult(0x0d, temp_col[2]) ^ Mult(0x09, temp_col[3])
			state[col * 4 + 1] = Mult(0x09, temp_col[0]) ^ Mult(0x0e, temp_col[1]) ^ Mult(0x0b, temp_col[2]) ^ Mult(0x0d, temp_col[3])
			state[col * 4 + 2] = Mult(0x0d, temp_col[0]) ^ Mult(0x09, temp_col[1]) ^ Mult(0x0e, temp_col[2]) ^ Mult(0x0b, temp_col[3])
			state[col * 4 + 3] = Mult(0x0b, temp_col[0]) ^ Mult(0x0d, temp_col[1]) ^ Mult(0x09, temp_col[2]) ^ Mult(0x0e, temp_col[3])
		}
		
	}

	if verbose {
		fmt.Println("After MixColumns:")
		printState(state[:])
	}
}

func AddRoundKey(state []byte, subKeys []byte, round int) {

	if verbose {
		fmt.Println("Round Key for round", round, ":")
		printState(subKeys[round * 16: round * 16 + 16])
	}

	for byte_pos := 0; byte_pos < 16; byte_pos++ {
		state[byte_pos] ^= subKeys[round * 16 + byte_pos]
	}
	
	if verbose {
		fmt.Println("After AddRoundKey:")
		printState(state[:])
	}
}

func printState(state []byte) {

	for row := 0; row < 4; row ++ {
		for col := 0; col < 4; col ++ {
			fmt.Print(hex.EncodeToString(state[row + col * 4:row + col *4 + 1]), " ")
		}
		fmt.Println()
	}
	fmt.Println()

	if debug {
		fmt.Println("Press 'Enter' to continue...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}

// NOT GOING TO WORK
func rcon(exponent int) byte {
	if exponent < 1 {
		panic("rcon value not expected")
	} else if exponent == 1 {
		return 1
	} else {
		return ModPol(uint16(2) << uint(exponent - 2))
	}
}

// keySchedule
func keySchedule(key []byte) []byte {

	// vars
	var expanded_keys [16 * 11]byte

	// first subkey is key itself
	copy(expanded_keys[:16], key[:])

	// expansion rounds
	for ii := 1; ii < 11; ii++ {

		current_index := ii * 16
		previous_index := current_index - 16

		//
		// first word of subkey
		//

		// rotWord
		copy(expanded_keys[current_index:current_index+4], append(expanded_keys[current_index - 3:current_index], expanded_keys[current_index - 4]))


		// subBytes
		for byte_pos := 0; byte_pos < 4; byte_pos++ {
			row := expanded_keys[current_index + byte_pos] >> 4
			col := expanded_keys[current_index + byte_pos] & 0x0f
			expanded_keys[current_index + byte_pos] = sbox0[row * 16 + col]
		}


		// xor
		for byte_pos := 0; byte_pos < 4; byte_pos++ {
			expanded_keys[current_index + byte_pos] = expanded_keys[previous_index + byte_pos] ^ expanded_keys[current_index + byte_pos]
			
		}
		// rcon
		expanded_keys[current_index] ^= rcon(ii)



		//
		// rest of the words
		//
		
		for ww := 4; ww < 16; ww++ {
			previous_previous := previous_index
			previous := current_index - 4

			expanded_keys[current_index + ww] = expanded_keys[previous_previous + ww] ^ expanded_keys[previous + ww]
		}
	}

	return expanded_keys[:]
}

//
func plaintextToState(plaintext []byte) []byte {
	
	if len(plaintext) < 16 {
		panic("nope nope")
	}

	var state []byte

	col_id := 0
	for byte_id := 0; byte_id < 16; byte_id++ {
		state_id := 4 * (byte_id % 4) + col_id
		if (byte_id % 4) == 3 {
			col_id ++
		}

		state[state_id] = plaintext[byte_id]
	}

	return state
}


// encryption
func encrypt(key []byte, plaintext []byte) []byte {
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
	for round = 1; round < 10; round ++ {
		fmt.Println("\nround", round, "\n")
		SubBytes(state, true)
		ShiftRows(state, true)
		MixColumns(state, true)
		AddRoundKey(state, subKeys, round)
	}

	// last round
	fmt.Println("round", round, "\n")
	SubBytes(state, true)
	ShiftRows(state, true)
	AddRoundKey(state, subKeys, round)

	return state
}

// 
func decrypt(key []byte, ciphertext []byte) []byte {
	// copy the state in a new state
	state := make([]byte, len(ciphertext))
	copy(state, ciphertext)

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

	// first round
	fmt.Println("round 10\n")
	AddRoundKey(state, subKeys, 10)
	ShiftRows(state, false)
	SubBytes(state, false)

	// rounds 1 to n-1

	for round := 9; round > 0; round -- {
		fmt.Println("\nround", round, "\n")
		AddRoundKey(state, subKeys, round)
		MixColumns(state, false)
		ShiftRows(state, false)
		SubBytes(state, false)
	}
	
	// post-whitening
	AddRoundKey(state, subKeys, 0)

	return state
}


//
func main(){

	// we assume plaintext is 16 bytes!

	plaintext := "theblockbreakers"
	//plaintext_bytes, _ := hex.DecodeString(plaintext)
	plaintext_bytes := []byte(plaintext)
	
	key_str := "2b7e151628aed2a6abf7158809cf4f3c"
	key, _ := hex.DecodeString(key_str)

	if verbose {
		fmt.Println("Plaintext:")
		printState(plaintext_bytes)
	}

	ciphertext := encrypt(key, plaintext_bytes)

	if verbose {
		fmt.Println("Ciphertext:")
		printState(ciphertext)
	}

	decrypted := decrypt(key, ciphertext)

	if verbose {
		fmt.Println("Decrypted:")
		printState(decrypted)
	}
	
}
	
