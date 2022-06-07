use crate::{
    aes::{self, AfghEncryption, AfghReEncryption},
    DecryptionSecretKey, EncryptionPublicKey, Error, ReencKey,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn afgh_encrypt(cleartext: &[u8], enc_pk: &[u8]) -> Result<Vec<u8>, u8> {
    let mut rng = rand::rngs::OsRng;
    let maybe_enc_pk: Option<_> = EncryptionPublicKey::from_bytes(
        enc_pk
            .try_into()
            .map_err(|_| Error::HeaderBadLength as u8)?,
    )
    .into();
    let enc_pk = maybe_enc_pk.ok_or(Error::InvalidEncryptionPk as u8)?;
    aes::afgh_encrypt(cleartext, &enc_pk, &mut rng)
        .map(|v| v.to_bytes())
        .map_err(|e| e as u8)
}

#[wasm_bindgen]
pub fn afgh_re_encrypt(afgh_encryption: &[u8], reenc_key: &[u8]) -> Result<Vec<u8>, u8> {
    let maybe_reenc_key: Option<_> = ReencKey::from_bytes(
        reenc_key
            .try_into()
            .map_err(|_| Error::ReencKeyBadLength as u8)?,
    )
    .into();
    let reenc = maybe_reenc_key.ok_or(Error::ReencKeyParseFailed as u8)?;
    let afghe = AfghEncryption::from_bytes(afgh_encryption).map_err(|e| e as u8)?;

    Ok(aes::afgh_re_encrypt(afghe, &reenc).to_bytes())
}

#[wasm_bindgen]
pub fn afgh_re_decrypt(afgh_reenc: &[u8], dec_sk: &[u8]) -> Result<Vec<u8>, u8> {
    let reenc = AfghReEncryption::from_bytes(afgh_reenc).map_err(|e| e as u8)?;
    let maybe_dk: Option<_> = DecryptionSecretKey::from_bytes(
        dec_sk
            .try_into()
            .map_err(|_| Error::DecryptionSkBadLength as u8)?,
    )
    .into();
    let dk = maybe_dk.ok_or(Error::DecryptionSkInvalid as u8)?;
    aes::afgh_re_decrypt(reenc, &dk).map_err(|e| e as u8)
}
