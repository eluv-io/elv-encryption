use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar};
use sha2::{Digest, Sha256};

use group::{ff::Field, prime::PrimeCurveAffine, Curve, Group};
use pairing::PairingCurveAffine;
use rand::RngCore;

mod aes;
mod key;
pub(crate) mod util;
pub use key::{PublicKey, SecretKey};
use util::ser_gt;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Divided by zero")]
    DivideByZero,
    #[error("Failed to parse scalar")]
    ScalarParseError,
    #[error("Failed to parse compressed g2 point")]
    G2AffineParseError,
    #[error("Failed to parse compressed gt point")]
    GtCompressedParseEror,
    #[error("AES Error")]
    AESError,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Message(Gt);

impl Message {
    const DST: [u8; 12] = *b"ELV_AFGH_MSG";
    pub fn random(rng: impl RngCore) -> Self {
        Message(Gt::random(rng))
    }

    pub fn derive_aes_key(&self) -> Result<[u8; 16], Error> {
        let mut gt_out = [0u8; 300];
        gt_out[..12].copy_from_slice(&Self::DST);
        ser_gt(&self.0, &mut gt_out[12..])?;
        let mut hasher = Sha256::new();
        hasher.update(&gt_out);
        Ok(hasher.finalize().as_slice().try_into().unwrap())
    }
}

pub enum EncryptedFor {
    A1,
    A2,
}

pub struct FirstLevelEncryption {
    enc_for: EncryptedFor,
    zak: Gt,
    mzk: Gt,
}

impl FirstLevelEncryption {
    pub fn encrypt(m: &Message, pk: &PublicKey, rng: impl RngCore) -> Self {
        let k = Scalar::random(rng);
        Self {
            enc_for: EncryptedFor::A1,
            zak: pk.za1 * k,
            mzk: (m.0 + (Gt::generator() * k)),
        }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Message, Error> {
        let opt_inv_scalar = match self.enc_for {
            EncryptedFor::A1 => sk.a1.invert(),
            EncryptedFor::A2 => sk.a2.invert(),
        };
        let inv_scalar = if opt_inv_scalar.is_none().into() {
            return Err(Error::DivideByZero);
        } else {
            opt_inv_scalar.unwrap()
        };
        let zk = self.zak * inv_scalar;
        Ok(Message(self.mzk - zk))
    }
}

pub struct SecondLevelEncryption {
    gk: G1Affine,
    mzak: Gt,
}

impl SecondLevelEncryption {
    pub const BYTES: usize = 48 + 288;
    pub fn encrypt(m: &Message, pk: &PublicKey, rng: impl RngCore) -> Self {
        let k = Scalar::random(rng);
        Self {
            gk: (G1Affine::generator() * k).to_affine(),
            mzak: m.0 + (pk.za1 * k),
        }
    }

    pub fn re_encrypt(&self, reenc_key: &ReencKey) -> FirstLevelEncryption {
        let rkab_affine: G2Affine = reenc_key.ga1b2.to_affine();
        let zbak = bls12_381::pairing(&self.gk, &rkab_affine);
        FirstLevelEncryption {
            enc_for: EncryptedFor::A2,
            zak: zbak,
            mzk: self.mzak,
        }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Message {
        let sub = bls12_381::pairing(&self.gk, &G2Affine::generator()) * sk.a1;
        Message(self.mzak - sub)
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let gk_cmp = self.gk.to_compressed();
        let gt_cmp = self.mzak.serialize_compressed();
        [gk_cmp.as_slice(), gt_cmp.as_slice()]
            .concat()
            .try_into()
            .unwrap()
    }
}

pub struct ReencKey {
    ga1b2: G2Projective,
}

impl ReencKey {
    pub fn delegate(ask: &SecretKey, bpk: &PublicKey) -> Self {
        Self {
            // bpk.ga2 = gb2
            ga1b2: bpk.ga2 * ask.a1,
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::prelude::ThreadRng;

    use super::*;
    use crate::SecretKey;

    struct Setup {
        a: SecretKey,
        b: SecretKey,
        msg: Message,
        rng: ThreadRng,
    }

    fn setup() -> Setup {
        let mut rng = rand::thread_rng();
        Setup {
            a: SecretKey::random(&mut rng),
            b: SecretKey::random(&mut rng),
            msg: Message::random(&mut rng),
            rng,
        }
    }

    #[test]
    fn first_level_encryption() {
        let Setup {
            a, msg, mut rng, ..
        } = setup();

        let first = FirstLevelEncryption::encrypt(&msg, &a.pubkey(), &mut rng);
        let dec = first.decrypt(&a).unwrap();
        assert_eq!(msg, dec);
    }

    #[test]
    fn second_level_encryption() {
        let Setup { a, b, msg, mut rng } = setup();

        let second = SecondLevelEncryption::encrypt(&msg, &a.pubkey(), &mut rng);
        let re_enc_key = ReencKey::delegate(&a, &b.pubkey());
        let delegated = second.re_encrypt(&re_enc_key);
        let dec = delegated.decrypt(&b).unwrap();
        assert_eq!(msg, dec);
    }
}
