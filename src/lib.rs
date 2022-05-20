use blstrs::{G1Projective, G2Affine, G2Projective, Gt, Scalar};

use group::{ff::Field, prime::PrimeCurveAffine, Curve, Group};
use pairing::PairingCurveAffine;
use rand::RngCore;

mod key;
pub use key::{PublicKey, SecretKey};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Divided by zero")]
    DivideByZero,
    #[error("Failed to parse scalar")]
    ScalarParseError,
}

pub enum EncryptedFor {
    FirstKey,
    SecondKey,
}

pub struct FirstLevelEncryption {
    enc_for: EncryptedFor,
    zak: Gt,
    mzk: Gt,
}

impl FirstLevelEncryption {
    pub fn encrypt(m: &Gt, pk: &PublicKey, rng: impl RngCore) -> Self {
        let k = Scalar::random(rng);
        Self {
            enc_for: EncryptedFor::FirstKey,
            zak: pk.za1 * k,
            mzk: (m + (Gt::generator() * k)),
        }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Gt, Error> {
        let opt_inv_scalar = match self.enc_for {
            EncryptedFor::FirstKey => sk.a1.invert(),
            EncryptedFor::SecondKey => sk.a2.invert(),
        };
        let inv_scalar = if opt_inv_scalar.is_none().into() {
            return Err(Error::DivideByZero);
        } else {
            opt_inv_scalar.unwrap()
        };
        let zk = self.zak * inv_scalar;
        Ok(self.mzk - zk)
    }
}

pub struct SecondLevelEncryption {
    gk: G1Projective,
    mzak: Gt,
}

impl SecondLevelEncryption {
    pub fn encrypt(m: &Gt, pk: &PublicKey, rng: impl RngCore) -> Self {
        let k = Scalar::random(rng);
        Self {
            gk: G1Projective::generator() * k,
            mzak: m + (pk.za1 * k),
        }
    }

    pub fn re_encrypt(&self, reenc_key: &ReencKey) -> FirstLevelEncryption {
        let rkab_affine: G2Affine = reenc_key.ga1b2.to_affine();
        let zbak = self.gk.to_affine().pairing_with(&rkab_affine);
        FirstLevelEncryption {
            enc_for: EncryptedFor::SecondKey,
            zak: zbak,
            mzk: self.mzak,
        }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Gt {
        let sub = self.gk.to_affine().pairing_with(&G2Affine::generator()) * sk.a1;
        self.mzak - sub
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
        msg: Gt,
        rng: ThreadRng,
    }

    fn setup() -> Setup {
        let mut rng = rand::thread_rng();
        Setup {
            a: SecretKey::random(&mut rng),
            b: SecretKey::random(&mut rng),
            msg: Gt::random(&mut rng),
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
