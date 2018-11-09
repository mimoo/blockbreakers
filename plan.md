# Block Breakers

## Intro

* maybe add the schneier paper "self study block cipher crypta"
    - I like its intro
* maybe add definition of a successful crypta (better than brute force)
* maybe a list of "block ciphers" and also a list of what else can encrypt? (stream ciphers, ARX, sponge, ...)
* what this is really is a cryptanalysis of a SPN no? or AES?

mentions? who helped me?

* Daniel Crowley gave me some feedback


## AES

* AES is a SPN block-cipher, there exist other constructions like feistel network (DES). But the attacks are mostly the same
    - also other ways of constructing ciphers: sponge, stream cipher, mansour something, ARX (chacha20)

add more "info" messages about:

* diffusion
* confusion

## SQUARE

* introduce it more clearly: "chosen-PT attack that uses a structural property of"
* I should mention who found it
* "verify a guess"

* idea: I could make step 5 and 6 do-able by giving some bits of the key. So you only have to do the attack on a fewer number of them.

## LINEAR

1. understand and create the linear approximation for the Sbox (program it, then use *Sage* to verify your result)
2. attack 1round-AES ?


## DIFFERENTIAL


1. explanation of the principle 
2. see how that works with OTP (start slow)
3. OTP + SBOX
4. differential characteristic

> a differential characteristic is a sequence of input and output differences to the rounds so that the output difference from one round corresponds to the input difference for the next round

4. difference distribution table (sage)
5. setup() <- 
6. test one of the delta (4/16) on the simple cipher (1 byte PT -> XOR k_1 -> SBOX -> XOR k_2 -> 1 byte CT)
7. **ON AES** <--
8. hard part is finding trails?



