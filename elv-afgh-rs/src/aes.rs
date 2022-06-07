use aes_gcm::{
    aead::{consts::U12, Aead},
    Aes128Gcm, NewAead, Nonce,
};
use rand::RngCore;

use crate::{
    DecryptionSecretKey, EncryptionPublicKey, Error, FirstLevelEncryption, Message, ReencKey,
    SecondLevelEncryption,
};

pub struct AfghEncryption {
    sl: SecondLevelEncryption,
    nonce: Nonce<U12>,
    ciphertext: Vec<u8>,
}

impl AfghEncryption {
    const HEADER_SIZE: usize = SecondLevelEncryption::BYTES + 12;
    pub fn to_bytes(mut self) -> Vec<u8> {
        let mut header = [self.sl.to_bytes().as_slice(), self.nonce.as_slice()]
            .concat()
            .to_vec();
        header.append(&mut self.ciphertext);
        header
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::HEADER_SIZE {
            return Err(Error::AfghEncParseFailed);
        }
        let sl: Option<_> = SecondLevelEncryption::from_bytes(
            &bytes[..SecondLevelEncryption::BYTES]
                .try_into()
                .expect("Checked length, QED"),
        )
        .into();
        let sl = sl.ok_or(Error::AfghEncParseFailed)?;
        let nonce = <Nonce<U12>>::clone_from_slice(
            &bytes[SecondLevelEncryption::BYTES..SecondLevelEncryption::BYTES + 12],
        );
        Ok(Self {
            sl,
            nonce,
            ciphertext: bytes[..Self::HEADER_SIZE].to_vec(),
        })
    }
}

pub fn afgh_encrypt(
    cleartext: &[u8],
    pk: &EncryptionPublicKey,
    mut rng: impl RngCore,
) -> Result<AfghEncryption, Error> {
    let m = Message::random(&mut rng);
    let sl = SecondLevelEncryption::encrypt(&m, pk, &mut rng);
    let aes_key = m.derive_aes_key();

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

pub fn afgh_re_decrypt(re: AfghReEncryption, sk: &DecryptionSecretKey) -> Result<Vec<u8>, Error> {
    let m: Option<Message> = re.fl.decrypt(&sk).into();
    let m = m.ok_or(Error::MessageDecryptError)?;
    let aes_key = m.derive_aes_key();

    let cipher = Aes128Gcm::new(&aes_key.into());
    cipher
        .decrypt(&re.nonce, &*re.ciphertext)
        .map_err(|_| Error::AESError)
}

#[cfg(test)]
mod tests {
    use crate::{
        afgh_encrypt, afgh_re_decrypt, afgh_re_encrypt, DecryptionSecretKey, EncryptionSecretKey,
        ReencKey,
    };

    #[test]
    fn test_aes() {
        let mut rng = rand::thread_rng();
        let a = EncryptionSecretKey::random(&mut rng);
        let b = DecryptionSecretKey::random(&mut rng);
        let rkab = ReencKey::delegate(&a, &b.pubkey());

        let clear = b"Diamonds cover up my chest, yours full of taco meat";
        let enc = afgh_encrypt(clear, &a.pubkey(), rng).expect("Encrypt failed");
        let re_enc = afgh_re_encrypt(enc, &rkab);

        let res = afgh_re_decrypt(re_enc, &b).expect("decrypt failed");

        assert_eq!(clear.to_vec(), res);
    }
}
