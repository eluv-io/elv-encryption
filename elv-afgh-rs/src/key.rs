use bls12_381::{G2Affine, G2Projective, Gt, Scalar};

use group::{ff::Field, Curve, Group};
use rand::RngCore;
use subtle::CtOption;

const COMPRESSED_GT_SIZE: usize = 576 / 2;
const COMPRESSED_G2_SIZE: usize = 96;
const SCALAR_SIZE: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionPublicKey {
    pub(crate) za1: Gt,
}

impl EncryptionPublicKey {
    const BYTES: usize = COMPRESSED_GT_SIZE;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        return self.za1.serialize_compressed();
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        Gt::deserialize_compressed(&bytes).map(|za1| Self { za1 })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecryptionPublicKey {
    pub(crate) gb2: G2Affine,
}

impl DecryptionPublicKey {
    const BYTES: usize = COMPRESSED_G2_SIZE;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        return self.gb2.to_compressed();
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        G2Affine::from_compressed(bytes).map(|ga2| Self { gb2: ga2 })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionSecretKey {
    pub(crate) a1: Scalar,
}

impl EncryptionSecretKey {
    pub fn pubkey(&self) -> EncryptionPublicKey {
        EncryptionPublicKey {
            za1: Gt::generator() * self.a1,
        }
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.a1.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> CtOption<Self> {
        Scalar::from_bytes(bytes).map(|a1| Self { a1 })
    }

    pub fn random(rng: impl RngCore) -> Self {
        Self {
            a1: Scalar::random(rng),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecryptionSecretKey {
    pub(crate) b2: Scalar,
}

impl DecryptionSecretKey {
    pub fn pubkey(&self) -> DecryptionPublicKey {
        DecryptionPublicKey {
            gb2: (G2Projective::generator() * self.b2).to_affine(),
        }
    }

    pub fn to_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.b2.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8; SCALAR_SIZE]) -> CtOption<Self> {
        Scalar::from_bytes(bytes).map(|b2| Self { b2 })
    }

    pub fn random(rng: impl RngCore) -> Self {
        Self {
            b2: Scalar::random(rng),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn decryption_serialization() {
        let dk = DecryptionSecretKey::random(&mut rand::thread_rng());
        let dkp = dk.pubkey();

        let dk_bytes = dk.to_bytes();
        let dkp_bytes = dkp.to_bytes();

        let dk_res = DecryptionSecretKey::from_bytes(&dk_bytes).unwrap();
        let dkp_res = DecryptionPublicKey::from_bytes(&dkp_bytes).unwrap();
        assert_eq!(dk, dk_res);
        assert_eq!(dkp, dkp_res);
    }

    #[test]
    fn encryption_serialization() {
        let ek = EncryptionSecretKey::random(&mut rand::thread_rng());
        let ekp = ek.pubkey();

        let ek_bytes = ek.to_bytes();
        let ekp_bytes = ekp.to_bytes();

        let ek_res = EncryptionSecretKey::from_bytes(&ek_bytes).unwrap();
        let ekp_res = EncryptionPublicKey::from_bytes(&ekp_bytes).unwrap();
        assert_eq!(ek, ek_res);
        assert_eq!(ekp, ekp_res);
    }
}
