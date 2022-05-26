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

#[cfg(test)]
mod tests {
    use crate::SecretKey;

    const SK_A: &str = "0e6cfd632776c53d7d30ca85532bda02bc7bb9581c8d1a965b7266b1427d3f872da6ec9ad9dbfdb8ef3a37ef0753debc0d01932276e11b78c2a9d0e4564bab0c";
    const PK_A: &str = "87acbe54f1faccacedc1f0fdd3225c811e4abb0ad5878a29710600b404b0e4ae809916186ba418103c43eeec4c088f9f0de1a2310836cc8d5208796b86f10ad25918f72e35f334a162c3b01c39815edc70a97f07e158fcedf5c89405b1070a781903870785245d9e836fc66ec396e8bee50feb1485d4d194f06e2435b1cd8dcebfe094156658b5f495a5153d8b241d450ab1f3abe7a77755cb684c38cbc2d993a36ee3553c1238878dfa64a548b24dec097b918ea3c1a1c87ebac4c747b4c0fc0e06621e1cfcb4c5279c6ac9d01a9721a7275cdd3637e9239875288436c64105dbf538360245ca20479fb3cf04d449da0052c138810b19df2795be811be7fcfcdef68b2dc632066253ccc194ae5a7e568e6c27747bed620604978b2ac93504ab058a0263ab140d350d06db75d365e97962598142dfb54f87c272d8656db2d42353824e2ca7fbb044c5e4189712eef6041540dc694af1c94bdb3ca6abbeb9991c6ac3602b62609d3044407dccd6459e9f7c476c8874d26e71beb683b0da5fd4db0a3fbcfcdc5a8f24fbb4fab137e92616352091ce6ec313bbc0c1af5bfda9753bad7d97cf05bea6910e4948b9bdc932341797fb01bbfb5b9caeb368653fe978d4bc01ad08c4d179b5606d27d8f43263d4520043aad5eb90143cc66cc7737d82540896d7b38cb530b51828cbcbb7b0d1482895bc922e43849ec0b4efc4382099c478970a2a175dcd2480fd524863953ac4096a9d95ff42c7cfc0ad0cbb88098c10a7208589a84f68b73aa928b57c8bb45fe70907690a334d829c988e05f7c611d7139cb9e99effc10f106af836c6fe140268ed595afc2f109eb5ad61f9e94fefb3bf0b55b5614f36a26b0771c6ae45652d136287851b2cb34f311ae71c2142be3cd43af02b83e76149b2989488eb5c568ef4c568497d329419307550c81bc51df8";
    #[test]
    fn test_serialization() {
        let mut ska_b = [0u8; 64];
        hex::decode_to_slice(SK_A, ska_b.as_mut()).unwrap();
        let ska = SecretKey::from_bytes(&ska_b).unwrap();
        let pka = ska.pubkey();
        let pka_b = pka.to_bytes().to_vec();

        assert_eq!(pka_b, hex::decode(PK_A).unwrap());

    }
}
