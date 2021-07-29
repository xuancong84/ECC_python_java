# ECC_python_java
Proof-of-concept code for Elliptic Curve Cryptography between Python and Java communication

Elliptic Curve Cryptography provides more secure and more efficient ways of encryption compared to RSA-based cryptography.

Key Size Comparison Table:

| Symmetric Key Size (bits) | RSA Size (bits) | Elliptic Curve Key Size (bits) |
| ------------------------- | --------------- | ------------------------------ |
| 80 | 1024  | 160 |
| 112 | 2048 | 224 |
| 128 | 3072 | 256 |
| 192 | 7680 | 384 |
| 256 | 15360 | 521 |

(References: [sectigo](https://sectigo.com/resource-library/rsa-vs-dsa-vs-ecc-encryption) [Wikipedia](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography))

However, there is a lack of mutually-compatible open-source implementation of Elliptic Curve Cryptography. Very often, due to the minute difference in the low-level implementation of some common cryptography algorithms, the encrypted data using one programming language cannot be correctly decrypted in another language.

This repository provides a reference, proof-of-concept, ready-to-deploy implementation of Elliptic Curve Cryptography (high-level uses ECC, low-level uses AES encryption) that is compatible between Java and Python. In the main function, it provides an example using the Curve NIST_P_256 (which provides equivalent security strength as RSA 3072-bit) and verifies that the data encrypted on the Java side can be correctly decrypted on the Python side, and vice versa. Moreover, for the Java side AES encryption, it contains both single-string encryption and stream-based encryption.

On Python side, this repository uses external Python packages *tinyec* and *cryptodome*. On Java side, it only uses native Java library.