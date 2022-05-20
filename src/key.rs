use blstrs::{G1Projective, G2Affine, G2Projective, Gt, Scalar, Compress};
use group::{ff::Field, Group};
use rand::RngCore;

use crate::Error;

pub struct PublicKey {
    pub(crate) za1: Gt,
    pub(crate) ga2: G2Projective,
}

pub struct SecretKey {
    pub(crate) a1: Scalar,
    pub(crate) a2: Scalar,
}

impl PublicKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let pk_out = [0u8; 64];
        self.za1.write_compressed(&mut pk_out[..48]);
        self.ga2.to_compressed()
        pk_out
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let out = [0u8; 64];
        let outa1 = self.a1.to_bytes();
        let outa2 = self.a2.to_bytes();
        out[..32].copy_from_slice(&outa1);
        out[32..].copy_from_slice(&outa2);
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let a1 = Scalar::from_bytes(
            <&[u8; 32]>::try_from(&bytes[..32]).expect("Must have exactly 32 bytes"),
        );
        let a2 = Scalar::from_bytes(
            <&[u8; 32]>::try_from(&bytes[32..]).expect("Must have exactly 32 bytes"),
        );
        if a1.is_some().into() && a2.is_some().into() {
            Ok(Self {
                a1: a1.unwrap(),
                a2: a2.unwrap(),
            })
        } else {
            Err(Error::ScalarParseError)
        }
    }

    pub fn random(mut rng: impl RngCore) -> Self {
        Self {
            a1: Scalar::random(&mut rng),
            a2: Scalar::random(&mut rng),
        }
    }

    pub fn pubkey(&self) -> PublicKey {
        PublicKey {
            za1: Gt::generator() * self.a1,
            ga2: G2Projective::generator() * self.a2,
        }
    }
}
