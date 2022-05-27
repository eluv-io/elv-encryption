use bls12_381::{Compress, G2Affine, G2Projective, Gt, Scalar};
use group::{ff::Field, Curve, Group};
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

fn ser_gt(gt: &Gt, out: &mut [u8]) -> Result<(), Error> {
    // as_mut_slice should make a new ref, so out should still point to a good region
    let mut le_out = [0u8; 288];
    gt.write_compressed(le_out.as_mut_slice())
        .map_err(|_| Error::GtCompressedParseEror)?;
    out.copy_from_slice(&le_out);
    Ok(())
}

fn deser_gt(b: &[u8; 288]) -> Result<Gt, Error> {
    Gt::read_compressed(b.as_ref()).map_err(|_| Error::GtCompressedParseEror)
}

impl PublicKey {
    const BYTES: usize = 288 + 96;

    pub fn to_bytes(&self) -> Result<[u8; Self::BYTES], Error> {
        let mut ret = [0u8; Self::BYTES];
        let ga2_bytes = self.ga2.to_affine().to_compressed();
        ret[..96].copy_from_slice(&ga2_bytes);
        ser_gt(&self.za1, &mut ret[96..])?;
        Ok(ret)
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> Result<Self, Error> {
        let ga2_bytes: &[u8; 96] = &bytes[..96].try_into().unwrap();
        let g2aff: G2Affine = Into::<Option<_>>::into(G2Affine::from_compressed(ga2_bytes))
            .ok_or(Error::G2AffineParseError)?;
        let ga2: G2Projective = g2aff.into();

        let za1_bytes: &[u8; 288] = &bytes[96..].try_into().unwrap();
        let za1 = deser_gt(za1_bytes)?;

        Ok(PublicKey { za1, ga2 })
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let outa1 = self.a1.to_bytes_be();
        let outa2 = self.a2.to_bytes_be();
        out[..32].copy_from_slice(&outa1);
        out[32..].copy_from_slice(&outa2);
        out
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        let a1 = Scalar::from_bytes_be(
            <&[u8; 32]>::try_from(&bytes[..32]).expect("Must have exactly 32 bytes"),
        );
        let a2 = Scalar::from_bytes_be(
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

#[cfg(test)]
mod tests {
    use crate::{SecretKey, PublicKey};
    use hex_literal::hex;

    const SK_A: [u8; 64] = hex!("0e6cfd632776c53d7d30ca85532bda02bc7bb9581c8d1a965b7266b1427d3f872da6ec9ad9dbfdb8ef3a37ef0753debc0d01932276e11b78c2a9d0e4564bab0c");
    const PK_A: [u8; PublicKey::BYTES] = hex!("87acbe54f1faccacedc1f0fdd3225c811e4abb0ad5878a29710600b404b0e4ae809916186ba418103c43eeec4c088f9f0de1a2310836cc8d5208796b86f10ad25918f72e35f334a162c3b01c39815edc70a97f07e158fcedf5c89405b1070a7855017d15b53be47dcd1a7f718c4eb690b53ad24b3169d0a1965e82a7965879501f2e30e9c4f664aa7873a6cab7e24e0460bfb3fde3d1dc89a5cdbb2d9418e6c90ad5887712323cce3de0ae7ef13f5f8b1868a0b6e8a7bf50fe4f899b9baf350b54aeb296df5e9e0504dd503e8e1fc182a0566240e1d67687a68ab75f3ba872753d887396b4c41225f74b235bc7d66813cba9aae1846c41f4b30c43310d5b21a35c2ca7756d40660cda91be9218670db65ebdfac3df77e9585413ff9e5c937c1673d3d144eacc53a3879d96d87259a72789a8d9bf54e65386bc896b7e01eb358c7d69f7901aa8a410a156529fd484260db5f2602b83d239518f8160706ecc45665db49bda6b4be1a4894db8e56273bd9893f9dbd25a230c9746c9fd93e1cb690b");


    #[test]
    fn test_serialization() {
        let ska = SecretKey::from_bytes(&SK_A).unwrap();
        let pka = ska.pubkey();

        let sk_bytes = ska.to_bytes();
        let pk_bytes = pka.to_bytes().unwrap();

        assert_eq!(SK_A, sk_bytes);
        assert_eq!(PK_A, pk_bytes);
    }
}
