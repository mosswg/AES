# This project is not cryptographically secure
This project is vulnerable to a number of attacks and makes no attempt to guard against them. This project has the primary purpose of making an AES implementation that is somewhat easy to understand and isn't hidden behind layers of abstraction. This project is hopefully a good learning tool for the basics of AES and can be used to further understand the nuances of different types. 

# Resources use
* [https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf](https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf)
* [https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf](https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf)
* [https://en.wikipedia.org/wiki/Advanced_Encryption_Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [https://www.angelfire.com/biz7/atleast/mix_columns.pdf](https://www.angelfire.com/biz7/atleast/mix_columns.pdf)

# How it works
## Overview
There are a different number of rounds based on the key size (128-bit, 196-bit, or 256-bit). This project uses 128-bit keys because they require the least amount of work. The steps are the same for each key size you just do more of the same step for the larger keys. The AES algorithm is broken into rounds. They also include a few initial steps and a few proceeding steps. The bytes of the message are referred to as the "state". AES operates within a [GF(2^8) finite field](#finite-field-math). While understanding finite field arithmatic is not strictly necessary for understanding AES implemations it is necessary for understanding the math behind the algorithm. \
Note: The state is stored as a vector of 32-bit integers. However, due to the way AES operates it is stored rotated from the way operations are done. This means that each 32-bit value in the vector is a column rather than a row.


## Notation
$\oplus$ denotes an xor operation. \
[ $b_{0}$ 	$b_{1}$ 	$b_{2}$ 	$b_{3}$] denotes the bytes of a 32-bit value where $b_{0}$ is the first byte in little endian and so on.

## Rounds
### Encryption
There are a different number of round for each key size (9, 11, or 13 for 128, 192, and 256-bit respectively). The rounds are performed after the initial steps and after the rounds are done the final steps are executed before returning the state as the ciphertext.

#### Initial Steps
1. [Key Expansion](#key-expansion) - AES includes a key schedule so that there is one key for every round.
2. [Add Round Key](#add-round-key) - The initial key (Not part of the key expansion) is added to the state.   

#### Round Steps
1. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array. 
2. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
3. [Mix Columns](#mix-columns) - The columns are mixed using either polynomial multiplication or matrix multiplication.
4. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.


#### Final Steps
1. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array.
2. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
3. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.

### Decryption
Decryption has the same number of round as encryption. The difference is that the initial steps, rounds, and final steps are exactly reversed from the encryption. To make things simpler, the round numbers will also be reversed (e.g. in AES-128 the first round would be round 9 then round 8 and so on).

#### Initial Steps
1. [Key Expansion](#key-expansion) - AES includes a key schedule so that there is one key for every round.
2. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.
3. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
4. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array.

#### Round Steps
1. [Add Round Key](#add-round-key) - The current round key (from the key expansion) is added to the state.
2. [Mix Columns](#mix-columns) - The columns are mixed using either polynomial multiplication or matrix multiplication.
3. [Shift Rows](#shift-rows) - The rows of the state are shifted by `r` places where `r` is the row index.
4. [Sub Bytes](#sub-bytes) - The bytes of the state are substituted using constant array. 

#### Final Steps
1. [Add Round Key](#add-round-key) - The initial key (Not part of the key expansion) is added to the state.


## Steps In Depth
### Notation
The state is represented below where ``si`` denotes the byte of the state and index ``i`` (e.g. ``s0`` is the 1st byte, ``s5`` is the 6th byte, and ``se`` is the 15th byte):
```
---------------------           ---------------------
| s0 | s4 | s8 | sc |       \   | s0 | s4 | s8 | sc |
| s1 | s5 | s9 | sd |  ------\  | s1 | s5 | s9 | sd |
| s2 | s6 | sa | se |  ------/  | s2 | s6 | sa | se |
| s3 | s7 | sb | sf |       /   | s3 | s7 | sb | sf |
---------------------           ---------------------
```
This would denote an operation where the state is not modified. With a real operation the left side would be the state before and the right side would be after the operation.


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
else if $(i \mod N) = 0$ then $W_{i} = W_{i-N} \oplus SubWord(RotWord(W_{i-1})) \oplus rcon_{i\ /\ N}$ \
else if $N > 6$ and $(i \mod N) = 4$ then $W_{i} = W_{i-N} \oplus SubWord(W_{i-1})$ \
else $W_{i} = W_{i-N} \oplus W_{i-1}$ \
\
These keys are placed into an array of 32-bit value where each set of four values represent a round key. The first round key is always the original key. The same formula is used for AES-192 and AES-256 with N being a higher value (6 and 8 respectively). Each round key is still 128-but but since the original key is larger than the state it is split into two round keys. The same keys are used for reversing the encryption however the are used in reverse. e.g. for AES-128 the 10th round key is used in place of the original key and vice versa.

### Add Round Key
#### Encryption
Using the round key of the current round gotten from the key expansion, each byte of the round key is xored with the state. \
\
This is done with the following where ``wi`` is the ``i``th byte of the current round key and ``ai`` is ``si xor wi``:
```
---------------------           ---------------------
| s0 | s4 | s8 | sc |       \   | a0 | a4 | a8 | ac |
| s1 | s5 | s9 | sd |  ------\  | a1 | a5 | a9 | ad |
| s2 | s6 | sa | se |  ------/  | a2 | a6 | aa | ae |
| s3 | s7 | sb | sf |       /   | a3 | a7 | ab | af |
---------------------           ---------------------
```
#### Decryption
Since addition is the same as substraction in GF( $2^8$ ) the encryption and decryption methods are the same for this step.

### Sub Bytes
S-Box Arrays: [Wikipedia](https://en.wikipedia.org/wiki/Rijndael_S-box)
#### Encryption
The Sub Bytes step uses an array of 256-bytes indexed with each byte in the state and the result in placed back into the state in the same position. The pre-computed S-Box values can be found at the link above. \
\
The state modification can be seen below where ``S`` is the S-Box array:
```
---------------------           ---------------------------------
| s0 | s4 | s8 | sc |       \   | S[s0] | S[s4] | S[s8] | S[sc] |
| s1 | s5 | s9 | sd |  ------\  | S[s1] | S[s5] | S[s9] | S[sd] |
| s2 | s6 | sa | se |  ------/  | S[s2] | S[s6] | S[sa] | S[se] |
| s3 | s7 | sb | sf |       /   | S[s3] | S[s7] | S[sb] | S[sf] |
---------------------           ---------------------------------
```

#### Decryption
The Inverse of Sub Bytes is the same process with an inverse array. This can be found in the link above.
#### Finding the S-Box Array Values
The values of the S-Box are found by the following steps: \
1. [Byte Inverse](#finite-field-inverse) - The inverse of the byte in GF( $2^8$ ) is found. We'll call this $b$ where $b_{i}$ is a single bit and $b_{0}$ is the least significant bit for the other steps.
2. Affine Transformation:
	1. Matrix Multiplication - The bits of the inverse are used in a matrix multiplication in GF( $2^8$ ).
	2. Vector Addition - The bits resulting from the Matrix Multiplaction are then xored with the bits representing 0x63.

The inverse S-Box array can be found by simply swapping the values and indexes of the S-Box array. \
\
The state modification for the inverse S-Box can be seen below where ``S`` is the Inverse S-Box array:
```
---------------------           ---------------------------------
| s0 | s4 | s8 | sc |       \   | S[s0] | S[s4] | S[s8] | S[sc] |
| s1 | s5 | s9 | sd |  ------\  | S[s1] | S[s5] | S[s9] | S[sd] |
| s2 | s6 | sa | se |  ------/  | S[s2] | S[s6] | S[sa] | S[se] |
| s3 | s7 | sb | sf |       /   | S[s3] | S[s7] | S[sb] | S[sf] |
---------------------           ---------------------------------
```


### Shift Rows
The shift rows step is performed by taking the state and moving each row based on its position. If we call the first row the 0th row it's easier to understand: \
The 0th row is not shifted. The 1st row is shift by one and so on. \
This mean that the operation as a whole looks like this:
```
---------------------           ---------------------
| s0 | s4 | s8 | sc |       \   | s0 | s4 | s8 | sc |
| s1 | s5 | s9 | sd |  ------\  | sd | s1 | s5 | s9 |
| s2 | s6 | sa | se |  ------/  | sa | se | s2 | s6 |
| s3 | s7 | sb | sf |       /   | s7 | sb | sf | s3 |
---------------------           ---------------------
```
### Mix Columns
Note: Most resources I found explain the multiplication for Mix Columns as using 0x1B as a polynomial without explaining why. 0x1B is just the regular irriducable polynomial with the last 8-bits chopped off. \
\
The mix columns step can be done in two ways. Polynomial multiplication and matrix multiplication. This project mainly uses the polynomial multiplication method, however the inverse function uses matrix multiplication. \
For mix columns we need to define a constant polynomial $a(x) = 3x^3 + x^2 + x + 2$ and a polynomial derived from the byte of the column $b(x) = b_{3}x^3 + b_{2}x^2 + b_{1}x + b_{0}$.

#### Polynomial method
For this method need to find $c(x)$ which is a seven-term polyonmial defined as $c(x) = a(x) \cdot b(x)$. We can also find $c(x)$ with: \
$c_{0} = a_{0} \cdot b_{0}$ \
$c_{1} = a_{1} \cdot b_{0} \oplus a_{0} \cdot b_{1}$ \
$c_{2} = a_{2} \cdot b_{0} \oplus a_{1} \cdot b_{1} \oplus a_{0} \cdot b_{2}$ \
$c_{3} = a_{3} \cdot b_{0} \oplus a_{2} \cdot b_{1} \oplus a_{1} \cdot b_{2} \oplus a_{0} \cdot b_{3}$ \
$c_{4} = a_{3} \cdot b_{1} \oplus a_{2} \cdot b_{2} \oplus a_{1} \cdot b_{3}$ \
$c_{5} = a_{3} \cdot b_{2} \oplus a_{2} \cdot b_{3}$ \
$c_{6} = a_{3} \cdot b_{3}$ \
Where $c(x) = c_{6}x^6 + c_{5}x^5 + c_{4}x^4 + c_{3}x^3 + c_{2}x^2 + c_{1}x + c_{0}$. \
We then find the values $d_{0}$, $d_{1}$. $d_{2}$, and $d_{3}$ from: \
$d_{0} = c_{0} \oplus c_{4}$ \
$d_{1} = c_{1} \oplus c_{5}$ \
$d_{2} = c_{2} \oplus c_{6}$ \
$d_{3} = c_{3}$ \
the $d$ values are then placed into the matrix where $b_{0}$ becomes $d_{0}$ and so on.

#### Matrix method
This method does a matrix multiplication of the matrix:
```
-----------------
| a0 | a3 | a2 | a1 |
| a1 | a0 | a3 | a2 |
| a2 | a1 | a0 | a3 |
| a3 | a2 | a1 | a0 |
-----------------
```
or
```
-----------------
| 2 | 3 | 1 | 1 |
| 1 | 2 | 3 | 1 |
| 1 | 1 | 2 | 3 |
| 3 | 1 | 1 | 2 |
-----------------
```
With the vector [ $b_{0}$ $b_{1}$ $b_{2}$ $b_{3}$ ]. The values of $d$ are then found with: \
$d_{0} = a_{0} \cdot b_{0} \oplus a_{3} \cdot b_{1} \oplus a_{2} \cdot b_{2} \oplus a_{1} \cdot b_{3}$ \
$d_{1} = a_{1} \cdot b_{0} \oplus a_{0} \cdot b_{1} \oplus a_{3} \cdot b_{2} \oplus a_{2} \cdot b_{3}$ \
$d_{2} = a_{2} \cdot b_{0} \oplus a_{1} \cdot b_{1} \oplus a_{0} \cdot b_{2} \oplus a_{3} \cdot b_{3}$ \
$d_{3} = a_{3} \cdot b_{0} \oplus a_{2} \cdot b_{1} \oplus a_{1} \cdot b_{2} \oplus a_{0} \cdot b_{3}$ \
or \
$d_{0} = 2 \cdot b_{0} \oplus 3 \cdot b_{1} \oplus 1 \cdot b_{2} \oplus 1 \cdot b_{3}$ \
$d_{1} = 1 \cdot b_{0} \oplus 2 \cdot b_{1} \oplus 3 \cdot b_{2} \oplus 1 \cdot b_{3}$ \
$d_{2} = 1 \cdot b_{0} \oplus 1 \cdot b_{1} \oplus 2 \cdot b_{2} \oplus 3 \cdot b_{3}$ \
$d_{3} = 3 \cdot b_{0} \oplus 1 \cdot b_{1} \oplus 1 \cdot b_{2} \oplus 2 \cdot b_{3}$ \
Keep in mind that this is [multiplication over GF(2^8)](#finite-field-multiplication):

#### State Modification For Either Method
The state modification of either of these method can be seen with the following where ``dij`` is $d_{j}$ of column ``i``:
```
---------------------           -------------------------
| s0 | s4 | s8 | sc |       \   | d00 | d10 | d20 | d30 |
| s1 | s5 | s9 | sd |  ------\  | d01 | d11 | d21 | d31 |
| s2 | s6 | sa | se |  ------/  | d02 | d12 | d22 | d32 |
| s3 | s7 | sb | sf |       /   | d03 | d13 | d23 | d33 |
---------------------           -------------------------
```

#### Decryption
For decryption mix columns uses the inverse of $a(x)$ which is $a'(x) = 11x^3 + 13x^2 + 9x + 14$. This project only implements the inverse of mix columns using matrix multiplication. \

The inverse matrix method does a matrix multiplication of the matrix using $a'(x)$:
```
-------------------------
| a'0 | a'3 | a'2 | a'1 |
| a'1 | a'0 | a'3 | a'2 |
| a'2 | a'1 | a'0 | a'3 |
| a'3 | a'2 | a'1 | a'0 |
-------------------------
```
or
```
---------------------
| 14 | 11 | 13 | 9  |
| 9  | 14 | 11 | 13 |
| 13 | 9  | 14 | 11 |
| 11 | 13 | 9  | 14 |
---------------------
```
With the vector [ $b_{0}$ $b_{1}$ $b_{2}$ $b_{3}$ ]. The values of $d$ are then found with: \
$d_{0} = a\prime_{0} \cdot b_{0} \oplus a\prime_{3} \cdot b_{1} \oplus a\prime_{2} \cdot b_{2} \oplus a\prime_{1} \cdot b_{3}$ \
$d_{1} = a\prime_{1} \cdot b_{0} \oplus a\prime_{0} \cdot b_{1} \oplus a\prime_{3} \cdot b_{2} \oplus a\prime_{2} \cdot b_{3}$ \
$d_{2} = a\prime_{2} \cdot b_{0} \oplus a\prime_{1} \cdot b_{1} \oplus a\prime_{0} \cdot b_{2} \oplus a\prime_{3} \cdot b_{3}$ \
$d_{3} = a\prime_{3} \cdot b_{0} \oplus a\prime_{2} \cdot b_{1} \oplus a\prime_{1} \cdot b_{2} \oplus a\prime_{0} \cdot b_{3}$ \
or \
$d_{0} = 14 \cdot b_{0} \oplus 11 \cdot b_{1} \oplus 13 \cdot b_{2} \oplus 9 \cdot b_{3}$ \
$d_{1} = 9 \cdot b_{0} \oplus 14 \cdot b_{1} \oplus 11 \cdot b_{2} \oplus 13 \cdot b_{3}$ \
$d_{2} = 13 \cdot b_{0} \oplus 9 \cdot b_{1} \oplus 14 \cdot b_{2} \oplus 11 \cdot b_{3}$ \
$d_{3} = 11 \cdot b_{0} \oplus 13 \cdot b_{1} \oplus 9 \cdot b_{2} \oplus 14 \cdot b_{3}$



## Finite Field Math
Other Resources: [Wikipedia](https://en.wikipedia.org/wiki/Finite_field_arithmetic), [Galois Field in Cryptography](https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf) \
Notes: This project uses Galois Field and Finite Field interchangably and unless explicitly stated the generating polynomial is $x^8 + x^4 + x^3 + x + 1$.
### Basics
Finite Fields are a field containing a finite number of elements from 0 to $p^n$ where $p$ is a prime and $n$ is a positive integer. For all math in this project $p$ is 2 and $n$ is 8 giving us the field GF( $2^8$ ).
Any number in GF( $2^8$ ) can be represented as a polynomial with: \
$b_{7}p^7 + b_{6}p^6 + b_{5}p^5 + b_{4}p^4 + b_{3}p^3 + b_{2}p^2 + b_{1}p^1 + b_{0}p^0$ \
Where $b$ is any 8-bit value and $b_{i}$ is the bit at $i$. And $p$ is 2 \
In an similar way the generating polynomial can be written as: \
$2^8 + 2^4 + 2^3 + 2 + 1$ or $[ 1 0 0 0 1 1 0 1 1 ]$ or $0x11b$ \
It is important to not that the generating polynomial is not a valid value within GF( $2^8$ ).

### Finite Field Addition
All addition in a finite field must be done modulo $p$. Since $p$ is always 2 in this project that means that all addition is modulo 2. Since addition modulo 2 is the same as the xor operation we can save a lot of computation time by just using xor instead of any addition operation.

### Finite Field Subtraction
Since every addition operation is modulo 2 and there is no concept of negative numbers in GF( $2^8$ ) every substraction is the exact same as addition and there for is just an xor operation.

### Finite Field Multiplication
Multiplication between two values on the finite field is significantly more complex. Multiplication can be acheive by taking the placement of every bit of one value and shifting the second value by that placement and xoring each of these together. The result of the muliplication is moduloed by the generating polynomial and the result of this modulo is the result of the multiplication. Example: \
$5 \cdot 5$ = $[ 1 0 1 ] \cdot [ 1 0 1 ]$ = $[ 1 0 1 ] \cdot [ 1 0 0 ] \oplus [ 1 0 1 ] \cdot [ 0 0 1 ]$ = $[ 1 0 1 ] \cdot 2^2 \oplus [ 1 0 1 ] \cdot 2^0$ = $[ 1 0 1 0 0 ] \oplus [ 0 0 1 0 1 ]$ = $[ 1 0 0 0 1 ]$ = 17 \
For this example $5 \cdot 5$ is less than the generating polynomial so the modulo is not done, however the result is still different due to using addition modulo 2.

### Finite Field Division
Division between two values in GF( $2^8$ ) is done the same way as long division, however we use [Finite Field Subtraction](#finite-field-subtraction). \
Example: \
$10\ /\ 7$ = $[ 1 0 1 0 ]\ /\ [ 1 1 1 ]$:
1. $[ 1 0 1 0] \oplus [ 1 1 1 ] \cdot 2^1$ = $[ 1 0 1 0 ] \oplus [ 1 1 1 0 ]$ = $[ 0 1 0 0 ]$
2. $[ 0 1 0 0] \oplus [ 1 1 1 ] \cdot 2^0$ = $[ 0 1 1 ]$ \

Thus the result is $2^1 + 2^0$ or 3 and the remainder is $[ 0 1 1 ]$ or 3.

### Finite Field Inverse
Finding the inverse in a finite field can be done with a modified version of the [Extended Euclidean Algorithm](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm). The difference is instead of finding $s_{i}$ and $t_{i}$ we find the auxiliary. The auxiliary is found using the following formula where a is the auxiliary and q is the quotient \
$a_{0} = 0$ \
$a_{1} = 1$ \
$a_{n} = a_{n - 2} \oplus a_{n - 1} \cdot q_{n}$ \
\
We use the reducing polynomial as the dividend and the number we want to find the inverse of as the divisor. \
For example to find the inverse of 0x15: \
\
First we divide the generating polynomial by 0x15: \
$[ 1 0 0 0 1 1 0 1 1 ]\ /\ [ 0 0 0 0 1 0 1 0 1 ]$ \
$[ 1 0 0 0 1 1 0 1 1 ] \oplus [ 0 0 0 0 1 0 1 0 1 ] \cdot 2^4$ = $[ 1 0 0 0 1 1 0 1 1 ] \oplus [ 1 0 1 0 1 0 0 0 0 ]$ = $[ 0 0 1 0 0 1 0 1 1 ]$ \
$[ 0 0 1 0 0 1 0 1 1 ] \oplus [ 0 0 0 0 1 0 1 0 1 ] \cdot 2^2$ = $[ 0 0 1 0 0 1 0 1 1 ] \oplus [ 0 0 1 0 1 0 1 0 0 ]$ = $[ 0 0 0 0 1 1 1 1 1 ]$ \
$[ 0 0 0 0 1 1 1 1 1 ] \oplus [ 0 0 0 0 1 0 1 0 1 ] \cdot 2^0$ = $[ 0 0 0 0 1 1 1 1 1 ] \oplus [ 0 0 0 0 1 0 1 0 1 ]$ = $[ 0 0 0 0 0 1 0 1 0 ]$ \
The quotient of the first division is $2^4 + 2^2 + 2^0$ and the remainder is $[ 0 0 0 0 0 1 0 1 0]$ \
\
We then divide 0x15 by this result: \
$[ 1 0 1 0 1 ]\ /\ [ 0 1 0 1 0]$ \
$[ 1 0 1 0 1 ] \oplus [ 0 1 0 1 0] \cdot 2^1$ = $[ 1 0 1 0 1 ] \oplus [ 1 0 1 0 0 ]$ = $[0 0 0 0 1]$ \
The quotient is $2^1$ and the remainder is $[ 0 0 0 0 1 ]$ \
\
The next step would be to divide the previous remainder by this remainder until our remainder is 1 but since this remainder is one we'll stop here. \
\
We can then create a table of our results
| Remainder               | Quotient           | Auxiliary                                                  |
| ----------------------- | ------------------ | ---------------------------------------------------------- |
| $[ 1 0 0 0 1 1 0 1 1 ]$ |	                   | $0$                                                        |
| $[ 0 0 0 0 1 0 1 0 1 ]$ |                    | $1$                                                        |
| $[ 0 0 0 0 0 1 0 1 0 ]$ | $2^4 + 2^2 + 2^0$  | $1(2^4 + 2^2 + 2^0) + 0$ = $2^4 + 2^2 + 2^0$               |
| $[ 0 0 0 0 0 0 0 0 1 ]$ | $2^1$              | $1 + 2^1 \cdot ( 2^4 + 2^2 + 2^0)$ = $2^5 + 2^3 + 2^1 + 1$ |

We take the auxiliary when our remainder is 1 and that is our inverse. So the inverse of 0x15 with the AES generating polynomial is $2^5 + 2^3 + 2^1 + 1$ or 0x2b
