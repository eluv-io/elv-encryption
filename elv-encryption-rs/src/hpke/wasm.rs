use wasm_bindgen::prelude::wasm_bindgen;
use super::*;

type KemK256 = hpke::kem::DhK256HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm128;

#[wasm_bindgen]
pub struct HpkeEncryptResult {
    encap: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl HpkeEncryptResult {
    pub fn encap(&self) -> Vec<u8> {
        self.encap.clone()
    }
    pub fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }
}

#[wasm_bindgen]
pub fn hpke_secp_encrypt(
    pk: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeEncryptResult, String> {
    let f = || {
        let pk = <KemK256 as Kem>::PublicKey::from_bytes(&pk)?;
        let mut rng = rand::rngs::OsRng;
        let (encap, mut enc_ctx) =
            hpke::setup_sender::<Aead, Kdf, KemK256, _>(&OpModeS::Base, &pk, info, &mut rng)?;

        let ciphertext = enc_ctx.seal(plaintext, aad)?;
        Ok(HpkeEncryptResult {
            encap: encap.to_bytes().to_vec(),
            ciphertext,
        })
    };
    f().map_err(|e: HpkeError| e.to_string())
}

#[wasm_bindgen]
pub fn hpke_secp_decrypt(
    sk: &[u8],
    info: &[u8],
    aad: &[u8],
    encap: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let f = || {
        let sk = <KemK256 as Kem>::PrivateKey::from_bytes(&sk)?;
        let encap = <KemK256 as Kem>::EncappedKey::from_bytes(&encap)?;
        let mut ctx =
            hpke::setup_receiver::<Aead, Kdf, KemK256>(&OpModeR::Base, &sk, &encap, info)?;
        ctx.open(ciphertext, aad)
    };
    f().map_err(|e| e.to_string())
}
