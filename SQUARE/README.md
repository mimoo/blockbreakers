## Set 2: Square Attack

The **Square attack**, first discovered on the block cipher *Square*, is a **structural attack**. It targets strange structural properties that persist across rounds of encryption in block ciphers.

There are no known "efficient" attacks on **full** *AES*. This means that if you want to break the *AES* algorithm, you will probably have to do a brute-force (or close). The observation behind the **Square attack** only persists for 3 rounds in AES. By extension, we will see how we can **break 4, 5 and even 6 rounds** of *AES* easily. For this set, you will need a good understanding of *AES* as well as an implementation of a reduced version of *AES*. If you're missing one or both of these requirements, I advise you to check the [set 1]() on *AES* first.

## Step 1. A persistant structure over 3 rounds

<!-- Explanation of the square attack (video?) -->
<!-- Video:
* avoid talking about AES
* avoid talking about 5 and 6 rounds
* Delta set: 1 byte is active at some position, and the rest have the same value across all items of the set in the same byte position (hard to explain).
-->

To check this hypothesis:

1. create a **reduced** version of *AES* with only 3 rounds in the encryption process.

If you did the previous set on *AES*, you can duplicate the `encrypt` function to a `EncryptWithRounds` that takes one more argument: the number of rounds. This will be useful as we will attack different reduced versions of *AES* in this set.

**Remember**: the last round does not apply a `MixColumns` transformation on the state.

1. Create a function named `setup` taking the main key as argument (use this key: `aa`) and producing a Λ-set with an active byte in index 0 and the same random value in all the other byte positions. Return the encryption of each elements of that Λ-set.
1. Verify that the ⊕ (XOR) of all the first bytes from the encrypted Λ-set is equal to zero. <!-- clear? -->
1. Verify this property for all the other byte positions.

If everything works out fine, you're ready for the next step.

## Step 2. Attacking 4 rounds with the Square attack

This property of *AES* allows the **Square attack** to trivially break 4 rounds of AES.

![video]()

If you understand this video, and feel confident about it, you should take a chance at solving this exercise without looking at the following steps. <!-- really? -->

1. Modify your reduced version of AES to now apply 4 rounds instead of the previous 3. Remember, the last round still does not use `MixColumns`.
1. Create a function named `reverseState` that takes a key guess of one byte, the position of that key guess and the encrypted Λ-set returned by the `setup` function. It should then reverse the byte at that position on every element of the Λ-set, up until the beginning of the last round. It should then return this new set of reversed byte.
1. Create a function named `checkKeyGuess` that takes the key guess of one byte, the set of byte values returned by the `reverseState` function and an associated array (dictionnary in python, map in Golang) to keep track of the valid and invalid guesses. The function should try to XOR all the byte of the value returned by `reverseState` and check if it is equal to 0. If it is, the associated value for that key guess should be set to `true`, otherwise it should be set to `false`.

1. Create a test to check that both `reverseState` and `checkKeyGuess` work. Use:

* The real byte of the key at index 5 as your key guess.
* The index 5.
* The Λ-set produced by `setup()`

If `checkKeyGuess()` finds out that the XOR is indeed 0, you're good. Otherwise meditate for 5 minutes and correct your code.

1. Create a function that checks the associated array modified by `checkKeyGuess()` to see if there is no more than one key guess valid. If there is only one valid key guess, then you've found the real key byte of the last subkey at this position. If you haven't, you need to test the remaining keys with a new Λ-set. Remember: you can use the `setup()` function for that: it is supposed to fill the non-active byte with a new (random or not) number at every call).

1. Now that you have the algorithm working for finding one byte of the last *subKey*, iterate it over all the bytes of the *subKey* until you found all of them. The algorithm should be really fast. On my year old device it runs in one second.

<!-- are these too detailed? Should I just give the big lines and let people implement their own algorithm? Since mine might not be too optimized -->

<!-- Now prove that you can do it and find out the key of that [download] -->

---

Test vectors?

## Step 3. Reversing AES' key schedule

We need to do that...

## Step 4. Attacking 5 rounds with the Square attack

Doing these attacks requires a deep understanding of *AES*, and this one step will re-inforce that feeling if you didn't already have it.

Now imagine that you an extra round at the end. You could guess 4 bytes of the last *subKey* to reverse the state until the end of the 4th round (second to last round). Right after XORing it with the penultimate *subKey*. Here you could also guess 4 bytes of that last *subKey* to continue reversing and perform the same attack as the previous one.

![image of this](http://i.imgur.com/VpFSfCE.jpg)

But there is a trick here. *AES* was beautifuly designed so that encryption and decryption could look similar. Remember this is encryption:

```
pre-whitening:
  AddRoundKey

n-1 round:
  SubBytes
  ShiftRows
  MixColumns
  AddRoundKey

last round:
  SubBytes
  ShiftRows
  AddRoundKey
```

Now the decryption:

```
last round:
  AddRoundKey
  ShiftRowsInv
  SubBytesInv

n-1 rounds:
  AddRoundKey
  MixColumnsInv
  ShiftRowsInv
  SubBytesInv

pre-whitening:
  AddRoundKey
```

This still doesn't look like what we have above. What about this:

```
pre-whitening:
  AddRoundKey

n-1 rounds:
  SubBytesInv
  ShiftRowsInv
  MixColumnsInv
  AddRoundKey

last round:
  SubBytesInv
  ShiftRowsInv
  AddRoundKey
```

<!-- who cares about that, we can just say that we can mutate mixcolumnsinv and addroundkey -->

Better no? This now looks exactly like the encryption algorithm. `SubBytesInv` and `ShiftRowsInv` were trivially commuted (if you don't understand how, you should stop here and think about it before going on). But what about `MixColumnsInv` and `AddRoundKey`? If it is true that we could invert them, then it would simplify our attack and we would only have to guess one byte of the second to last round *subKey*.

Not so fast. The AddRoundKey is a bit different here. What really happens is that the `MixColumnsInv` (and `MixColumns` as well) is linear with repsect to the colum input. This means:

`MixColumnsInv(state XOR Round Key) = MixColumnsInv(state) XOR MixColumnsInv(Round Key)`

Back to our attack, this means that at the output of the second to last round, instead of having to inverse `AddRoundKey` first, we can inverse `MixColumnsInv` first and get back to 1 byte. Then we just have to guess what is the byte being XORed to this from `MixColumsInv(Round Key)`.

![solved trick](http://i.imgur.com/C1Bj7i3.jpg)

---

1. Modify your reduced version of *AES* to now apply 5 rounds of encryption.
1. `reverseState` now should take a 5-byte key guess (one byte is for the `InverseKey` byte), the encrypted Λ-set and an index for these key guesses. Here's an example of what byte positions could be associated to what indexes:

```
 idx=0     idx=1    idx=2    idx=3
x . . .   . x . .  . . x .  . . . x
. . . x   x . . .  . x . .  . . x .
. . x .   . . . x  x . . .  . x . . 
. x . .   . . x .  . . . x  x . . .
```

The function should reverse the last round. Remember, after the `ShiftRowsInv` operations the byte positions should represent a column of the state.

![diagram again?]()

After reversing the last round, do not stop: the function should reverse the first `MixColumnsInv` of the 4th round (which is the first operation to reverse if we use our trick).

The function should return a one byte set (the reversed state in one byte position) right after using the `MixColumnsInv` operation, and right before the `AddRoundKey` with the `MixColumnsInv(Round Key)` (remember our trick).

````
x . . .
. . . .
. . . .
. . . .
```

We could return the entire column, but we do not need to.

<!-- FREAKING test vectors for this -->

1. Now use your algorithm to find the last *subKey* column by column.

---

**Test Vectors**

encrypt 000000...
with key 2b7e151628aed2a6abf7158809cf4f3c

your last sub key should be:

```
d4 7c ca 11
d1 83 f2 f9
c6 9d b8 15
f8 87 bc bc
```

Here. our first 4 bytes we will test are

```
d4, f9, b8, 87
```

<!-- make diagram -->

Try to find what trick key will fit this. (answer is `0x90`)

---

This attack starts to take too long already.

## Step 4. Attacking 6 rounds with the Square attack

We can also gain a round in the very beginning, we need to guess 4 key byte of the first subkey to create a delta set AFTER the first round


