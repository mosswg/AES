# This project is not cryptographically safe
This project is vulnerable to a number of attacks and makes no attempt to guard against them. This project has the primary purpose of making an AES implementation that is somewhat easy to understand and isn't hidden behind layers of abstraction. This project is hopefully a good learning tool for the basics of AES and can be used to further understand the nuances of different types. 

# Resources use
* [https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf](https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf)
* [https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf](https://sites.math.washington.edu/~morrow/336_12/papers/juan.pdf)
* [https://en.wikipedia.org/wiki/Advanced_Encryption_Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
* [https://www.angelfire.com/biz7/atleast/mix_columns.pdf](https://www.angelfire.com/biz7/atleast/mix_columns.pdf)

# How it works
## Overview
There are a different number of rounds based on the key size (128-bit, 196-bit, or 256-bit). This project uses 128-bit keys because they require the least amount of work. The steps are the same for each key size you just do more of the same step for the larger keys. The AES algorithm is broken into rounds with the 9, 11 or 13 for each key size respectively. They also include a few initial steps and a few proceeding steps. The bytes of the message are referred to as the "state". AES operates within a [GF(2^8) finite field](#finite-field-math). While understanding finite field arithmatic is not strictly necessary for understanding AES implemations it is necessary for understanding the math behind the algorithm. \

## Notation
$\oplus$ denotes an xor operation. \
[$b_{0}$\t$b_{1}$\t$b_{2}$\t$b_{3}$] denotes the bytes of a 32-bit value where $b_{0}$ is the first byte in little endian and so on.

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



## Steps In Depth
### Round Constants
if $i = 1$ then $rc_{i} = 1$ \
if $i > 1$ and $rc_{i-1} < 0x80$ then $rc_{i} = 2 \cdot rc_{i-1} \
if $i > 1$ and $rc_{i-1} > 0x80$ then $rc_{i} = 2 \cdot rc_{i-1} \oplus 0x11b$ \
$rc$ values are then expanded from an byte value into four byte round constant values with: {$rc_{i}$\t$0$\t$0$\t$0$} \

### Key Expansion
The key expansion uses [Round Constants](#round-constants) and two functions:
* RotWord - a one-byte ciicular roation such that RotWord([$b_{0}$\t$b_{1}$\t$b_{2}$\t$b_{3}$]) = [$b_{1}$\t$b_{2}$\t$b_{3}$\t$b_{0}$]
* SubWord - a direct substituition using the [S-Box](#sub-bytes).

The key expansion is done following the formula where N is key size in 32-bit words (e.g. for AES-128 N is 4), K is byte array of the key, and W is the array of byte representing the round keys:
if $i < N$ then $W_{i} = K_[i}$ \
else if $(i mod N) = 0$ then $W_{i} = W_{i-N} \oplus SubWord(RotWord(W_{i-1})) \oplus rcon_{i / N}$ \
else if $N > 6$ and $(i mod N) = 4$ then $W_{i} = W_{i-N} \cplus SubWord(W_{i-1})$
else $W_{i} = W_{i-N} \cplus W_{i-1}

### Add Round Key


### Sub Bytes


### Shift Rows


### Mix Columns



### Finite Field Math
Other Resources: [Wikipedia](https://en.wikipedia.org/wiki/Finite_field_arithmetic)
