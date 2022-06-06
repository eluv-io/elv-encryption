use bls12_381::{G2Affine, G2Projective, Gt, Scalar};

use group::{Curve, Group, ff::Field};
use rand::RngCore;
use subtle::CtOption;


const COMPRESSED_GT_SIZE: usize = 576 / 2;
const COMPRESSED_G2_SIZE: usize = 96;
const SCALAR_SIZE: usize = 32;

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
        Self { a1: Scalar::random(rng) }
    }
}

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
        Self { b2: Scalar::random(rng) }
    }
}
