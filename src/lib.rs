use bls12_381::{G1Affine, G2Affine, Gt, Scalar};
use sha2::{Digest, Sha256};

use group::{ff::Field, Curve, Group};
use rand::RngCore;

mod aes;
pub use aes::*;

mod key;
pub use key::*;
use subtle::CtOption;

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
    #[error("Failed to decrypt message")]
    MessageDecryptError,
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

    pub fn derive_aes_key(&self) -> [u8; 16] {
        let mut gt_out = [0u8; 300];
        gt_out[..12].copy_from_slice(&Self::DST);
        let gtb = self.0.serialize_compressed();
        gt_out[12..].copy_from_slice(&gtb);
        let mut hasher = Sha256::new();
        hasher.update(&gt_out);
        hasher.finalize().as_slice().try_into().unwrap()
    }

    pub fn to_bytes(&self) -> [u8; 288] {
        self.0.serialize_compressed()
    }

    pub fn from_bytes(bytes: &[u8; 288]) -> CtOption<Self> {
        Gt::deserialize_compressed(bytes).map(|gt| Self(gt))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct FirstLevelEncryption {
    zak: Gt,
    mzk: Gt,
}

impl FirstLevelEncryption {
    pub const BYTES: usize = 288 * 2;

    pub fn decrypt(&self, sk: &DecryptionSecretKey) -> CtOption<Message> {
        sk.b2.invert().map(|b2_inv| {
            let zk = self.zak * b2_inv;
            Message(self.mzk - zk)
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let zak = self.zak.serialize_compressed();
        let mzk = self.mzk.serialize_compressed();
        [zak.as_slice(), mzk.as_slice()]
            .concat()
            .try_into()
            .unwrap()
    }

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        Gt::deserialize_compressed(&bytes[..48].try_into().unwrap()).and_then(|zak| {
            Gt::deserialize_compressed(&bytes[48..].try_into().unwrap())
                .map(|mzk| Self { zak, mzk })
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct SecondLevelEncryption {
    gk: G1Affine,
    mzak: Gt,
}

impl SecondLevelEncryption {
    pub const BYTES: usize = 48 + 288;
    pub fn encrypt(m: &Message, pk: &EncryptionPublicKey, rng: impl RngCore) -> Self {
        let k = Scalar::random(rng);
        Self {
            gk: (G1Affine::generator() * k).to_affine(),
            mzak: m.0 + (pk.za1 * k),
        }
    }

    pub fn re_encrypt(&self, reenc_key: &ReencKey) -> FirstLevelEncryption {
        let zbak = bls12_381::pairing(&self.gk, &reenc_key.ga1b2);
        FirstLevelEncryption {
            zak: zbak,
            mzk: self.mzak,
        }
    }

    pub fn decrypt(&self, sk: &EncryptionSecretKey) -> Message {
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

    pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
        G1Affine::from_compressed(&bytes[..48].try_into().unwrap()).and_then(|gk| {
            Gt::deserialize_compressed(&bytes[48..].try_into().unwrap())
                .map(|mzak| Self { gk, mzak })
        })
    }
}

pub struct ReencKey {
    ga1b2: G2Affine,
}

impl ReencKey {
    pub fn delegate(owner: &EncryptionSecretKey, target: &DecryptionPublicKey) -> Self {
        Self {
            ga1b2: (target.gb2 * owner.a1).to_affine(),
        }
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.ga1b2.to_compressed()
    }

    pub fn from_bytes(bytes: &[u8; 96]) -> CtOption<Self> {
        G2Affine::from_compressed(bytes).map(|ga1b2| Self { ga1b2 })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::prelude::ThreadRng;

    use super::*;
    use crate::{DecryptionSecretKey, EncryptionSecretKey};

    struct Setup {
        a: EncryptionSecretKey,
        b: DecryptionSecretKey,
        msg: Message,
        rng: ThreadRng,
    }

    fn setup() -> Setup {
        let mut rng = rand::thread_rng();
        Setup {
            a: EncryptionSecretKey::random(&mut rng),
            b: DecryptionSecretKey::random(&mut rng),
            msg: Message::random(&mut rng),
            rng,
        }
    }

    #[test]
    fn second_level_encryption() {
        let Setup { a, b, msg, mut rng } = setup();

        let second = SecondLevelEncryption::encrypt(&msg, &a.pubkey(), &mut rng);
        assert_eq!(msg, second.decrypt(&a));

        let re_enc_key = ReencKey::delegate(&a, &b.pubkey());
        let delegated = second.re_encrypt(&re_enc_key);
        let dec = delegated.decrypt(&b).unwrap();
        assert_eq!(msg, dec);
    }

    const SKA: [u8; 32] = hex!("0ffe91b02e7832a7cfe71332a71f7713720214586c637db74e952cfd0d41eb1d");
    const SKB: [u8; 32] = hex!("110f0e62be00cc54c70f4e213dd666ec25c3b4dfbae9392fdbae42fc572d6b4b");
    const PKA: [u8; 288] = hex!("130c3a481eabf6ed24c13c8a7b9c83bcfcf82ef39b084f7fc3c9b880ff49ed64db8b22bdbe3ad5191c410af6b72996570d68a382b25149c102172e9ca141251cd31efe9b9b6bf89afd58a57edfe947148cd0275689b091407f1d223caf6fca39118f9825cfb5ec92e0c27e074d86656292f25122d7b9a7d12a87efcadb8c1a9945db7268c608b84836f15e1d680333f705d866a73f25e8e28932223d99f7fca99c6af5c3c272f704207ab4983b090d9a708bdcc8b62072fc2769caf6954aec0418a694aad15208ab0377c4672edb9a79d639fd99557ff24991cfda62981de848c808bcb47f8e44396d0286b6689806870b6d9bd23af0f3e0af2e38cd59c17e3e502e50351858aa569ef2331e07436ff6992ac42cc5ac3993eda37dae05d7f765");
    const PKB: [u8; 96] = hex!("a16715978fd2e3853ff2d10774c46708c49945a7125e13146faba53624bf117190cdafa568488c70d23b73d30aae250c1748af58cccc4896b9c44a0239d8226295918d18bd89f0563477d19889905961d281018056fca053c881a0b5e057db4f");
    const MSG: [u8; 288] = hex!("1744383a66242091c4e894b89069de59b5e54c72944ccab5e5a5b5a337fa482c750c9e57b26d8ce7c25d7927c911636f0463ca9a79ecce1b52666199a62665a0235aef83d8fe0b297575eec5a2a184305601d7db94b70959007eb30c1ebae39c16324e8b8a3dfd7d354978e49f1aaf26f77b8c7b8b493385e4abb7b074561debd44c4e48db14ee18b1af79c7396519e0156f81b1407d31e9d6872f8d9d54d22a621d82a65edaeae43d594905b696296e54a9ad16e9654027edcbf1894f4d0ed2094009988ef8743bc2392ecaa8f488da6a8cc5dce5df1f00ad5a2c9c591a10850c2a7a138d331984d4223e84766e296902f6becbaabf94af721574b51976eeb5879e33f60972b4ba909b4152da3a854a78a4a7ff9b2afb081e82a51fe083b10a");
    const SLE: [u8; 336] = hex!("886787abb933d1bf9cd53f2e9f1e8dc69872b6ea916934839b3dcf532a37b9add87f43d7393a93f927850eb1f5a2608505b8d3e1dca5098ce7a9bd2203bb78584dbd177b2711778f75d9fd400187af6687f63b97b7cd372aed8063402c818d5c0973c8fd011f901ad1a4d698b4a3a3d92a93e09f9e74f06fcff0259140e631aeaf2d0edc1aab6d4e06ed946983d3e997130b9d8f1db5c38130c0f966752f412fe757eb67bb526d36d05ad31cfe26792137e43183d5ba8cd5fba2f0e726526fc206cd362c2d43d41738de5b4894db9f21b5a7d5b531e6ddbd0b5addb8de543e666951065658a3bd7b00721b47839a806f0ac80aa03d6b9195db7f4c741abe6af64f9334322a6afc3fee1d45a60be0a2390638d87d153d0da1e3d83293e6cc52770e6cad2b666df9578ac77efb0cbb49f6a29199eb387f619f41f0a953f246e956ed3e50c1ef913a3523d661b8486d7840");
    const RKE: [u8; 96] = hex!("b632ba81b8cf1c73f6fc4e17f77fb989104261f537f92a2c1f34c13b0d8f497a2e0f01e881160981c3ed088b9de7937e1035dc2302ecc01c6bc651aaff30a218b408fe59bc688dbc2733831face8adb2b7b5d77394bb1ccf0f45cf4422ddfbdc");
    const FLE: [u8; 576] = hex!("0c24974d5bca4939b34f0fc8643d93442b3db60f9830f54148f5db0acc12c12a9066f8f7bd9fc30aed0e25b9015b99e70cacfb8d17d0084823c57427f1e10ca5e3a0577292233c55f21dd5a5f6b7f0fcae09013e71ec3529d7d2cc5178594eec0ba362b84b75aa0e8e070f802626845f1b956efba8bb0a1915e4377fd415c364cdfd7960e48be7f14addd3808bafe75601f44e96f6cbf5c8572226da05735105843d2c403248f46d17b9b00145721dcdbff719aadfe1bf3e9242ea4eda7839910672b413fd474852fd130d29fda030f0029dc69fc2f325b4fc6f37fd6e7a913e6dde48518cabec646b12a52599b966ae15ddc50a25fcb0d2fd5f3d1efe5988416b1cb82c0dd85bb2949c36d91052224a205de9cce45d510f3111e45ca4223ff705b8d3e1dca5098ce7a9bd2203bb78584dbd177b2711778f75d9fd400187af6687f63b97b7cd372aed8063402c818d5c0973c8fd011f901ad1a4d698b4a3a3d92a93e09f9e74f06fcff0259140e631aeaf2d0edc1aab6d4e06ed946983d3e997130b9d8f1db5c38130c0f966752f412fe757eb67bb526d36d05ad31cfe26792137e43183d5ba8cd5fba2f0e726526fc206cd362c2d43d41738de5b4894db9f21b5a7d5b531e6ddbd0b5addb8de543e666951065658a3bd7b00721b47839a806f0ac80aa03d6b9195db7f4c741abe6af64f9334322a6afc3fee1d45a60be0a2390638d87d153d0da1e3d83293e6cc52770e6cad2b666df9578ac77efb0cbb49f6a29199eb387f619f41f0a953f246e956ed3e50c1ef913a3523d661b8486d7840");

    #[test]
    fn consistent_serialization() {
        let ska = EncryptionSecretKey::from_bytes(&SKA).unwrap();
        let pka = ska.pubkey();
        assert_eq!(pka.to_bytes(), PKA);

        let skb = DecryptionSecretKey::from_bytes(&SKB).unwrap();
        let pkb = skb.pubkey();
        assert_eq!(pkb.to_bytes(), PKB);

        let sle = SecondLevelEncryption::from_bytes(&SLE).unwrap();
        let rke = ReencKey::from_bytes(&RKE).unwrap();

        let fle = sle.re_encrypt(&rke);
        assert_eq!(fle.to_bytes(), FLE);

        let msg = fle.decrypt(&skb).unwrap();
        assert_eq!(msg.to_bytes(), MSG);
    }
}
