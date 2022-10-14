# This project is not cryptographically secure
This project is vulnerable to a number of attacks and makes no attempt to guard against them. This project has the primary purpose of making an AES implementation that is somewhat easy to understand and isn't hidden behind layers of abstraction. This project is hopefully a good learning tool for the basics of AES and can be used to further understand the nuances of different types. 

# Resources use
* [https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf](https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf)
* [https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf](https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf)
* [https://en.wikipedia.org/wiki/Advanced_Encryption_Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [https://www.angelfire.com/biz7/atleast/mix_columns.pdf](https://www.angelfire.com/biz7/atleast/mix_columns.pdf)

# How it works
## Overview
There are a different number of rounds based on the key size (128-bit, 196-bit, or 256-bit). This project uses 128-bit keys because they require the least amount of work. The steps are the same for each key size you just do more of the same step for the larger keys. The AES algorithm is broken into rounds. They also include a few initial steps and a few proceeding steps. The bytes of the message are referred to as the "state". AES operates within a [GF( $2^8$ ) finite field](#finite-field-math). While understanding finite field arithmatic is not strictly necessary for understanding AES implemations it is necessary for understanding the math behind the algorithm.

## Notation
$\oplus$ denotes an xor operation. \
[ $b_{0}$ 	$b_{1}$ 	$b_{2}$ 	$b_{3}$] denotes the bytes of a 32-bit value where $b_{0}$ is the first byte in little endian and so on.

## Rounds
### Encryption
There are a different number of round for each key size (9, 11, or 13 for 128, 192, and 256-bit respectively). The rounds are performed after the initial steps and after the rounds are done the final steps are executed before returning the state as the ciphertext.

### Initial Steps
1. [Key Expansion](#key-expansion) - AES includes a key schedule so that there is one key for every round.
2. [Add Round Key](#add-round-key) - The initial key (Not part of the key expansion) is added to the state.   

### Round Steps
1. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array. 
2. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
3. [Mix Columns](#mix-columns) - The columns are mixed using either polynomial multiplication or matrix multiplication.
4. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.


### Final Steps
1. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array.
2. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
3. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.

### Decryption
Decryption has the same number of round as encryption. The difference is that the initial steps, rounds, and final steps are exactly reversed from the encryption. To make things simpler, the round numbers will also be reversed (e.g. the first round would be round 9 then round 8 and so on).

### Initial Steps 
1. [Key Expansion](#key-expansion) - AES includes a key schedule so that there is one key for every round.
2. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.
3. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
4. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array.

### Round Steps
1. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.
2. [Mix Columns](#mix-columns) - The columns are mixed using either polynomial multiplication or matrix multiplication.
3. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
4. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array. 

### Final Steps
1. [Add Round Key](#add-round-key) - The initial key (Not part of the key expansion) is added to the state.


## Steps In Depth
### Round Constants
if $i = 1$ then $rc_{i} = 1$ \
if $i > 1$ and $rc_{i-1} < 0x80$ then $rc_{i} = 2 \cdot rc_{i-1}$ \
if $i > 1$ and $rc_{i-1} > 0x80$ then $rc_{i} = 2 \cdot rc_{i-1} \oplus 0x11b$ \
\
$rc$ values are then expanded from an byte value into four byte round constant values with: [ $rc_{i}$		$0$		$0$		$0$ ]

### Key Expansion
The key expansion uses [Round Constants](#round-constants) and two functions:
* RotWord - a one-byte ciicular roation such that RotWord([ $b_{0}$		$b_{1}$		$b_{2}$		$b_{3}$ ]) = [ $b_{1}$		$b_{2}$		$b_{3}$		$b_{0}$ ]
* SubWord - a direct substituition using the [S-Box](#sub-bytes).

The key expansion is done following the formula where N is key size in 32-bit words (e.g. for AES-128 N is 4), K is byte array of the key, and W is the array of byte representing the round keys: \
\
if $i < N$ then $W_{i} = K_{i}$ \
else if $(i \mod N) = 0$ then $W_{i} = W_{i-N} \oplus SubWord(RotWord(W_{i-1})) \oplus rcon_{i / N}$ \
else if $N > 6$ and $(i \mod N) = 4$ then $W_{i} = W_{i-N} \oplus SubWord(W_{i-1})$ \
else $W_{i} = W_{i-N} \oplus W_{i-1}$ \
\
These keys are placed into an array of 32-bit value where each set of four values represent a round key. The first round key is always the original key. \
The same formula is used for AES-192 and AES-256 with N being a higher value (6 and 8 respectively). Each round key is still 128-but but since the original key is larger than the state it is split into two round keys. \
The same keys are used for reversing the encryption however the are used in reverse. e.g. for AES-128 the 10th round key is used in place of the original key and vice versa.

### Add Round Key
#### Encryption
Using the round key of the current round gotten from the key expansion, each byte of the round key is xored with the state. This is done with the following where each value is 32-bit and b is the state before the operation, w is the round key, and s is the resulting state. \
$$
[ b_{0}		b_{1}		b_{2}		b_{3} ] \oplus [ w_{0}		w_{1}		w_{2}		w_{3} ] = [ s_{0}		s_{1}		s_{2}		s_{3} ]
$$
#### Decryption
Since addition is the same as substraction in GF( $2^8$ ) the encryption and decryption methods are the same for this step.

### Sub Bytes
S-Box Arrays: [Wikipedia](https://en.wikipedia.org/wiki/Rijndael_S-box)
#### Encryption
The Sub Bytes step uses an array of 256-bytes indexed with each byte in the state and the result in placed back into the state in the same position. The pre-computed S-Box values can be found at the link above.
#### Decryption
The Inverse of Sub Bytes is the same process with an inverse array. This can be found in the link above.
#### Deriving the S-Box Array
The values of the S-Box are found by the following steps: \
1. [Byte Inverse](#finite-field-inverse) - The inverse of the byte in GF( $2^8$ ) is found. We'll call this $b$ where $b_{i}$ is a single bit and $b_{0}$ is the least significant bit for the other steps.
2. Affine Transformation:
	1. Matrix Multiplication - The bits of the inverse are used in a matrix multiplication in GF( $2^8$ ).
	2. Vector Addition - The bits resulting from the Matrix Multiplaction are then xored with the bits representing 0x63.

${\displaystyle {\begin{bmatrix}s_{0}\\s_{1}\\s_{2}\\s_{3}\\s_{4}\\s_{5}\\s_{6}\\s_{7}\end{bmatrix}}={\begin{bmatrix}1&0&0&0&1&1&1&1\\1&1&0&0&0&1&1&1\\1&1&1&0&0&0&1&1\\1&1&1&1&0&0&0&1\\1&1&1&1&1&0&0&0\\0&1&1&1&1&1&0&0\\0&0&1&1&1&1&1&0\\0&0&0&1&1&1&1&1\end{bmatrix}}{\begin{bmatrix}b_{0}\\b_{1}\\b_{2}\\b_{3}\\b_{4}\\b_{5}\\b_{6}\\b_{7}\end{bmatrix}}+{\begin{bmatrix}1\\1\\0\\0\\0\\1\\1\\0\end{bmatrix}}}$ \
\
The inverse S-Box array can be found by simply swapping the values and indexes of the S-Box array.


### Shift Rows


### Mix Columns



### Finite Field Math
Other Resources: [Wikipedia](https://en.wikipedia.org/wiki/Finite_field_arithmetic)
