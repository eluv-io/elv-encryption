use aes_gcm::{
    aead::{consts::U12, Aead},
    Aes128Gcm, NewAead, Nonce,
};
use rand::RngCore;

use crate::{
    Error, FirstLevelEncryption, Message, PublicKey, ReencKey, SecondLevelEncryption, SecretKey,
};

pub struct AfghEncryption {
    sl: SecondLevelEncryption,
    nonce: Nonce<U12>,
    ciphertext: Vec<u8>,
}

pub fn afgh_encrypt(
    cleartext: &[u8],
    pk: &PublicKey,
    rng: impl RngCore,
) -> Result<AfghEncryption, Error> {
    let m = Message::random(&mut rng);
    let sl = SecondLevelEncryption::encrypt(&m, pk, &mut rng);
    let aes_key = m.derive_aes_key()?;

    let cipher = Aes128Gcm::new(&aes_key.into());
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce: Nonce<U12> = nonce_bytes.into();

    let ciphertext = cipher
        .encrypt(&nonce, cleartext)
        .map_err(|_| Error::AESError)?;
    Ok(AfghEncryption {
        sl,
        nonce,
        ciphertext,
    })
}

pub struct AfghReEncryption {
    fl: FirstLevelEncryption,
    nonce: Nonce<U12>,
    ciphertext: Vec<u8>,
}

pub fn afgh_re_encrypt(afghe: AfghEncryption, rk: &ReencKey) -> AfghReEncryption {
    AfghReEncryption {
        fl: afghe.sl.re_encrypt(&rk),
        nonce: afghe.nonce,
        ciphertext: afghe.ciphertext,
    }
}

pub fn afgh_re_decrypt(re: AfghReEncryption, sk: &SecretKey) -> Result<Vec<u8>, Error> {
    let m = re.fl.decrypt(&sk)?;
    let aes_key = m.derive_aes_key()?;

    let cipher = Aes128Gcm::new(&aes_key.into());
    cipher
        .decrypt(&re.nonce, &*re.ciphertext)
        .map_err(|_| Error::AESError)
}
