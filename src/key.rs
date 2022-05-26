use bls12_381::{G2Affine, G2Projective, Gt, Scalar};
use group::{ff::Field, Curve, Group};
use rand::RngCore;
use subtle::CtOption;

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
    const BYTES: usize = 576 + 96;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut ret = [0u8; Self::BYTES];
        let ga2_bytes = self.ga2.to_affine().to_compressed();
        let za1_bytes = self.za1.to_bytes();
        ret[..96].copy_from_slice(&ga2_bytes);
        ret[96..].copy_from_slice(&za1_bytes);
        ret
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        let ga2_bytes: &[u8; 96] = &bytes[..96].try_into().unwrap();
        let za1_bytes: &[u8; 576] = &bytes[96..].try_into().unwrap();
        G2Affine::from_compressed(ga2_bytes).and_then(|ga2| {
            Gt::from_bytes(za1_bytes).map(|za1| PublicKey {
                za1,
                ga2: ga2.into(),
            })
        })
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
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
