package main

import(
	"fmt"
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

// creates tupples of (pt1, pt2, ct1, ct2) where pt1[pos] ^ pt2[pos] = delta

type tuple struct {
	pt1 []byte
	pt2 []byte
	ct1 []byte
	ct2 []byte
}

// key: key to encrypt with AES
// positions: list of positions for active differences
// deltas: list of differences respective to their positions
// max: maximum tuples you want to get
func setup(key []byte, positions []int, deltas []byte, max int) []tuple {

	var tuples []tuple
	r := rand.New(rand.NewSource(99)) // TODO: replace with time?

	for number := 0 ; number < max; number++ {

		// create a random tuple and add it to the tuple list
		var tup tuple
		tup.pt1 = make([]byte, 16)
		tup.pt2 = make([]byte, 16)
		r.Read(tup.pt1)
		r.Read(tup.pt2)
		
		// create the deltas in the right pos
		for idx, position := range positions{
			delta := deltas[idx]

			tup.pt2[position] = tup.pt1[position] ^ delta

		}

		// encrypt the plaintexts
		tup.ct1 = EncryptWithRounds(2, key, tup.pt1)
		tup.ct2 = EncryptWithRounds(2, key, tup.pt2)
		
		// add the tup to the list
		tuples = append(tuples, tup)
	}

	//
	return tuples
}




func display_diff_char() map[uint16]int {

	// the map input->output: number of possibilities
	delta := make(map[uint16]int, 256 * 256)

	// fill the map
	var uno, duo uint16
	for uno = 0; uno < 256; uno++ {
		for duo = 0; duo < 256; duo++ {
			input_diff := uno ^ duo
			output_diff := uint16(sbox0[uno] ^ sbox0[duo])
			delta[(input_diff << 8) ^ output_diff] ++
		}
	}

	// display the map
	for idx := 0; idx < 256 * 256; idx ++ {
		if idx % 256 == 0 {
			fmt.Println()
		}
		
		fmt.Print(" ", delta[uint16(idx)])
	}

	return delta
}

func display_good_differentials(delta map[uint16]int) {

	found := 0
	for idx := 0; idx < 256 * 256; idx ++ {
		if d := delta[uint16(idx)]; d > 2 {
			found++
			d_in := idx >> 8
			d_out := idx & 0xFF
			fmt.Printf("#%d - input delta: %02x, output delta: %02x, number: %d\n", found, d_in, d_out, d)
		}
	}

}

func main(){
	//display_diff_char()

	key := uint16(0x91c3)

	fmt.Println("encryption of 0 is", simple_cipher2(key, 0))
}

