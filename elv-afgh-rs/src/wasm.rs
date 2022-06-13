use crate::{
    DecryptionSecretKey, EncryptionPublicKey, Error, FirstLevelEncryption, Message, ReencKey,
    SecondLevelEncryption,
};
use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
pub fn afgh_gen(enc_pk: &[u8]) -> Result<Vec<u8>, u8> {
    let mut rng = rand::rngs::OsRng;
    let maybe_enc_pk: Option<_> = EncryptionPublicKey::from_bytes(
        enc_pk
            .try_into()
            .map_err(|_| Error::HeaderBadLength as u8)?,
    )
    .into();
    let enc_pk = maybe_enc_pk.ok_or(Error::InvalidEncryptionPk as u8)?;
    let m = Message::random(&mut rng);
    let aes_key = m.derive_aes_key();
    let sl = SecondLevelEncryption::encrypt(&m, &enc_pk, &mut rng);
    let sl_bytes = sl.to_bytes();
    Ok([aes_key.as_ref(), sl_bytes.as_ref()].concat().to_vec())
}

#[wasm_bindgen]
pub fn afgh_re_encrypt(sle: &[u8], reenc_key: &[u8]) -> Result<Vec<u8>, u8> {
    let maybe_reenc_key: Option<_> = ReencKey::from_bytes(
        reenc_key
            .try_into()
            .map_err(|_| Error::ReencKeyBadLength as u8)?,
    )
    .into();
    let reenc_key = maybe_reenc_key.ok_or(Error::ReencKeyParseFailed as u8)?;
    let maybe_sle: Option<SecondLevelEncryption> = SecondLevelEncryption::from_bytes(
        sle.try_into().map_err(|_| Error::SLEInvalidLength as u8)?,
    )
    .into();
    let sle = maybe_sle.ok_or(Error::SLEParseFailed as u8)?;
    let fle = sle.re_encrypt(&reenc_key).to_bytes();
    Ok(fle.to_vec())
}

#[wasm_bindgen]
pub fn afgh_re_decrypt(reenc: &[u8], dec_sk: &[u8]) -> Result<Vec<u8>, u8> {
    let maybe_fle: Option<FirstLevelEncryption> = FirstLevelEncryption::from_bytes(
        reenc
            .try_into()
            .map_err(|_| Error::FLEInvalidLength as u8)?,
    )
    .into();
    let fle = maybe_fle.ok_or(Error::FLEParseFailed as u8)?;
    let maybe_dk: Option<_> = DecryptionSecretKey::from_bytes(
        dec_sk
            .try_into()
            .map_err(|_| Error::DecryptionSkBadLength as u8)?,
    )
    .into();
    let dk = maybe_dk.ok_or(Error::DecryptionSkInvalid as u8)?;
    let m: Option<Message> = fle.decrypt(&dk).into();
    let m = m.ok_or(Error::MessageDecryptError as u8)?;
    let aes_key = m.derive_aes_key();
    Ok(aes_key.to_vec())
}
