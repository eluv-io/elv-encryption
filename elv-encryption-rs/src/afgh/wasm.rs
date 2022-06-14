use super::{
    DecryptionSecretKey, EncryptionPublicKey, EncryptionSecretKey, Error, FirstLevelEncryption,
    Message, ReencKey, SecondLevelEncryption,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn gen_decryption_sk() -> Vec<u8> {
    let dec_sk = DecryptionSecretKey::random(rand::rngs::OsRng);
    dec_sk.to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn decryption_sk_to_pk(dec_sk: &[u8]) -> Result<Vec<u8>, String> {
    let maybe_dec_sk: Option<DecryptionSecretKey> = DecryptionSecretKey::from_bytes(
        &dec_sk
            .try_into()
            .map_err(|_| Error::DecryptionSkBadLength.to_string())?,
    )
    .into();
    let dec_sk = maybe_dec_sk.ok_or(Error::DecryptionSkInvalid.to_string())?;
    Ok(dec_sk.pubkey().to_bytes().to_vec())
}

#[wasm_bindgen]
pub fn gen_encryption_sk() -> Vec<u8> {
    let enc_sk = EncryptionSecretKey::random(rand::rngs::OsRng);
    enc_sk.to_bytes().to_vec()
}

#[wasm_bindgen]
pub fn encryption_sk_to_pk(enc_sk: &[u8]) -> Result<Vec<u8>, String> {
    let maybe_enc_sk: Option<EncryptionSecretKey> = EncryptionSecretKey::from_bytes(
        &enc_sk
            .try_into()
            .map_err(|_| Error::EncryptionSkBadLength.to_string())?,
    )
    .into();
    let enc_sk = maybe_enc_sk.ok_or(Error::EncryptionSkInvalid.to_string())?;
    Ok(enc_sk.pubkey().to_bytes().to_vec())
}

#[wasm_bindgen]
pub struct KeyAndEncryption {
    key: Vec<u8>,
    sle: Vec<u8>,
}

#[wasm_bindgen]
impl KeyAndEncryption {
    /// Gets the 16 byte AES 128 key
    pub fn get_key(&self) -> Vec<u8> {
        self.key.clone()
    }
    /// Gets the SLE bytes
    pub fn get_sle(&self) -> Vec<u8> {
        self.sle.clone()
    }
}

/// Generate an aes key and second level encryption of that aes key under the given encryption
/// public key
#[wasm_bindgen]
pub fn afgh_gen(enc_pk: &[u8]) -> Result<KeyAndEncryption, String> {
    let mut rng = rand::rngs::OsRng;
    let maybe_enc_pk: Option<_> = EncryptionPublicKey::from_bytes(
        enc_pk
            .try_into()
            .map_err(|_| Error::HeaderBadLength.to_string())?,
    )
    .into();
    let enc_pk = maybe_enc_pk.ok_or(Error::InvalidEncryptionPk.to_string())?;
    let m = Message::random(&mut rng);
    let aes_key = m.derive_aes_key();
    let sl = SecondLevelEncryption::encrypt(&m, &enc_pk, &mut rng);
    let sl_bytes = sl.to_bytes();
    Ok(KeyAndEncryption {
        key: aes_key.to_vec(),
        sle: sl_bytes.to_vec(),
    })
}

/// Re-encrypt the second level encryption using the re-encryption key. Returns a first level
/// encryption which can be directly decrypted using `afgh_re_decrypt`.
#[wasm_bindgen]
pub fn afgh_re_encrypt(sle: &[u8], reenc_key: &[u8]) -> Result<Vec<u8>, String> {
    let maybe_reenc_key: Option<_> = ReencKey::from_bytes(
        reenc_key
            .try_into()
            .map_err(|_| Error::ReencKeyBadLength.to_string())?,
    )
    .into();
    let reenc_key = maybe_reenc_key.ok_or(Error::ReencKeyParseFailed.to_string())?;
    let maybe_sle: Option<SecondLevelEncryption> = SecondLevelEncryption::from_bytes(
        sle.try_into()
            .map_err(|_| Error::SLEInvalidLength.to_string())?,
    )
    .into();
    let sle = maybe_sle.ok_or(Error::SLEParseFailed.to_string())?;
    let fle = sle.re_encrypt(&reenc_key).to_bytes();
    Ok(fle.to_vec())
}

/// Decrypt a re-encrypted ciphertext to recover a 16 byte ciphertext using the provided decryption
/// secret key
#[wasm_bindgen]
pub fn afgh_re_decrypt(reenc: &[u8], dec_sk: &[u8]) -> Result<Vec<u8>, String> {
    let maybe_fle: Option<FirstLevelEncryption> = FirstLevelEncryption::from_bytes(
        reenc
            .try_into()
            .map_err(|_| Error::FLEInvalidLength.to_string())?,
    )
    .into();
    let fle = maybe_fle.ok_or(Error::FLEParseFailed.to_string())?;
    let maybe_dk: Option<_> = DecryptionSecretKey::from_bytes(
        dec_sk
            .try_into()
            .map_err(|_| Error::DecryptionSkBadLength.to_string())?,
    )
    .into();
    let dk = maybe_dk.ok_or(Error::DecryptionSkInvalid.to_string())?;
    let m: Option<Message> = fle.decrypt(&dk).into();
    let m = m.ok_or(Error::MessageDecryptError.to_string())?;
    let aes_key = m.derive_aes_key();
    Ok(aes_key.to_vec())
}
