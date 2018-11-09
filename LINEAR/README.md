# Set 3: Linear Cryptanalysis

## Info

> in most cases resistance against differential and linear cryptanalysis are the criteria that shape a block cipher and the other known attacks are only considered later and resistance against them can be obtained with small modifications in the original design

* known plaintext attack
* ciphertext-only attack is possible
* statistical attack
* "use linear approximation to model nonlinear steps in the encryption process" -> for one round
- then you try to generalize that to many rounds, but the quality get lost as the rounds increase
* analysis is done on linear combination on bits of a ciphertext
* linear is newer than differential (Matsui 1993)
* quote the books that helped me (The Block Cipher Companion, A Tutorial on Linear and Differential Cryptanalysis by Howard M. Heys, A Salad of Block Ciphers, by Roberto Avanzi)


## Plan

1. linear approximation (test vectors)

http://doc.sagemath.org/html/en/reference/cryptography/sage/crypto/mq/sbox.html
