# elv-encryption
This repository implements a couple types of encryption used in Eluvio's content fabric.

| Feature                  | Rust impl           | Go impl |
| ------------------------ | ------------------- | ------- |
| AFGH Proxy Re-Encryption | `elv-encryption-rs` | `qafgh` |
| Secp256k1-based HPKE     | `elv-encryption-rs` | `qhpke` |


## AFGH

Contained in `elv-afgh-rs` is an implementation of the [AFGH Proxy Re-Encryption Scheme](https://web.archive.org/web/20220313022340/https://eprint.iacr.org/2005/028.pdf) for Eluvio's Content Fabric.

BLS12-381 is chosen as the underlying curve specification used. Rust and golang implementations are provided. 

### Details 

The following choices are made for the cryptoscheme provided in the paper. Additive group notation is used.
FLE/SLE stand for First/Second Level Encryption.

| Item                 | Paper Symbols       | Type                         | Length (Bytes) |
| -------------------- | ------------------- | ---------------------------- | -------------- |
| Encryptor Secret Key | $a_1$               | $\mathbb{Z}_q$               | 32             |
| Encryptor Public Key | $Z{a_1}$            | $\mathbb{G}_T$               | 288            |
| Decryptor Secret Key | $b_2$               | $\mathbb{Z}_q$               | 32             |
| Decryptor Public Key | $g b_2$             | $\mathbb{G}_2$               | 96             |
| Raw Message          | $m$                 | $\mathbb{G}_T$               | 288            |
| SLE Message ($E_2$)  | $gk, m + Z {a_1 k}$ | $\mathbb{G}_1, \mathbb{G}_T$ | 336            |
| FLE Message ($E_1$)  | $Za_1k, m + Z k$    | $\mathbb{G}_T, \mathbb{G}_T$ | 576            |
| ReEncryption Key     | $g {a_1 b_2}$       | $\mathbb{G}_2$               | 96             |

Notably, $\mathbb{G1}$ and $\mathbb{G2}$ are chosen such that we minimize the size of SLE messages. 

* Scalars in $\mathbb{Z}_q$ are serialized in canonical form as little endian.
* G1/G2 elements are compressed and serialized according to the zkcrypto specification.
* GT elements are compressed using Torus based compression and serialized as FP6 elements in big endian form.


## HPKE

[Hybrid public key encryption](https://datatracker.ietf.org/doc/rfc9180/) is a standard which allows for encryption of data for a specific public key. 
It is very similarly to afgh, since it has a shared secret that derives an AES key which encrypts data, but does so without the ability for a proxy to re-encrypt that data for a third party. 
The implementation given uses a fork of [rust-hpke](https://github.com/rozbb/rust-hpke) and [Cloudflare's circl](https://github.com/cloudflare/circl) which include the option to use `secp256k1` keys, as that curve is not present in the spec, but is still reasonable to use. 
