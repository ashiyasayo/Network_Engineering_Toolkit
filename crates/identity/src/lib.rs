//! Node identity 的平台安全儲存、首次建立與 material validation。

#![forbid(unsafe_code)]

use getrandom::fill as random_fill;
use keyring::Entry;
use nettool_error::{ErrorCode, NetToolError};
use rcgen::{CertifiedKey, KeyPair, PublicKeyData, generate_simple_self_signed};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const SECRET_MAGIC: &[u8; 8] = b"NTID\0\0\0\x01";
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
const MAX_PRIVATE_KEY_BYTES: usize = 64 * 1024;
const SERVICE_NAME: &str = "com.nettool.node-identity";
const ACCOUNT_NAME: &str = "default";

/// 可供 TLS transport 與 Hello negotiation 使用的本機持久身分。
pub struct IdentityMaterial {
    /// 首次建立後保持不變的 128-bit logical Node ID。
    pub node_id: [u8; 16],
    /// 本機 mTLS certificate chain；目前第一個元素為 identity certificate。
    pub certificate_chain: Vec<CertificateDer<'static>>,
    /// 從平台安全儲存區取出的 PKCS#8 identity private key。
    pub private_key: PrivateKeyDer<'static>,
}

/// 私密資料儲存邊界；production implementation 不得使用一般檔案或 `SQLite`。
pub trait SecureSecretStore {
    /// 讀取 identity secret；不存在時回傳 `None`。
    ///
    /// # Errors
    ///
    /// 平台安全儲存區無法存取、被鎖定或資料讀取失敗時回傳錯誤。
    fn get_secret(&self) -> Result<Option<Vec<u8>>, NetToolError>;

    /// 原子建立或更新 identity secret。
    ///
    /// # Errors
    ///
    /// 平台安全儲存區無法保存資料時回傳錯誤。
    fn set_secret(&self, secret: &[u8]) -> Result<(), NetToolError>;
}

/// 使用 OS native credential store 的 production secret store。
///
/// keyring backend 依平台映射至 macOS Keychain、Windows Credential Manager 與 Linux
/// Secret Service；服務不可用時會失敗，不會退回 plaintext 檔案。
pub struct PlatformKeyringStore {
    entry: Entry,
}

impl PlatformKeyringStore {
    /// 開啟 `NetTool` 的固定 identity credential entry。
    ///
    /// # Errors
    ///
    /// 目前平台沒有可用的 native credential store 時回傳錯誤。
    pub fn open() -> Result<Self, NetToolError> {
        Entry::new(SERVICE_NAME, ACCOUNT_NAME)
            .map(|entry| Self { entry })
            .map_err(|error| keyring_error(&error))
    }
}

impl SecureSecretStore for PlatformKeyringStore {
    fn get_secret(&self) -> Result<Option<Vec<u8>>, NetToolError> {
        match self.entry.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(keyring_error(&error)),
        }
    }

    fn set_secret(&self, secret: &[u8]) -> Result<(), NetToolError> {
        self.entry
            .set_secret(secret)
            .map_err(|error| keyring_error(&error))
    }
}

/// 只透過指定 secure store 載入或首次建立 Node identity。
pub struct IdentityProvider<S> {
    store: S,
    subject_names: Vec<String>,
}

impl<S: SecureSecretStore> IdentityProvider<S> {
    /// 建立 provider；subject names 會寫入首次產生的 certificate SAN。
    ///
    /// # Errors
    ///
    /// Subject name 空白、重複或數量超出安全上限時回傳錯誤。
    pub fn new(store: S, subject_names: Vec<String>) -> Result<Self, NetToolError> {
        validate_subject_names(&subject_names)?;
        Ok(Self {
            store,
            subject_names,
        })
    }

    /// 載入既有 identity；若不存在則產生 Node ID、金鑰與 certificate 後先安全保存。
    ///
    /// # Errors
    ///
    /// Secure store、亂數、憑證產生或既有 secret validation 失敗時回傳錯誤。
    pub fn load_or_create(&self) -> Result<IdentityMaterial, NetToolError> {
        if let Some(secret) = self.store.get_secret()? {
            return decode_secret(&secret);
        }
        let material = generate_identity(&self.subject_names)?;
        let secret = encode_secret(&material)?;
        self.store.set_secret(&secret)?;
        decode_secret(&secret)
    }
}

fn generate_identity(subject_names: &[String]) -> Result<IdentityMaterial, NetToolError> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_names.to_vec())
        .map_err(|error| {
            identity_error(format!("cannot generate identity certificate: {error}"))
        })?;
    Ok(IdentityMaterial {
        node_id: random_node_id()?,
        certificate_chain: vec![cert.der().clone()],
        private_key: PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    })
}

fn random_node_id() -> Result<[u8; 16], NetToolError> {
    loop {
        let mut node_id = [0_u8; 16];
        random_fill(&mut node_id).map_err(|error| {
            NetToolError::new(
                ErrorCode::RandomFailed,
                format!("cannot generate Node ID: {error}"),
                false,
            )
        })?;
        if node_id != [0; 16] {
            return Ok(node_id);
        }
    }
}

fn encode_secret(material: &IdentityMaterial) -> Result<Vec<u8>, NetToolError> {
    let certificate = material
        .certificate_chain
        .first()
        .ok_or_else(|| identity_error("identity certificate chain is empty"))?;
    let key = material.private_key.secret_der();
    validate_lengths(certificate.len(), key.len())?;
    let certificate_length = u32::try_from(certificate.len())
        .map_err(|_| identity_error("identity certificate is too large"))?;
    let key_length =
        u32::try_from(key.len()).map_err(|_| identity_error("identity key is too large"))?;
    let mut secret = Vec::with_capacity(32 + certificate.len() + key.len());
    secret.extend_from_slice(SECRET_MAGIC);
    secret.extend_from_slice(&material.node_id);
    secret.extend_from_slice(&certificate_length.to_be_bytes());
    secret.extend_from_slice(&key_length.to_be_bytes());
    secret.extend_from_slice(certificate);
    secret.extend_from_slice(key);
    Ok(secret)
}

fn decode_secret(secret: &[u8]) -> Result<IdentityMaterial, NetToolError> {
    if secret.len() < 32 || &secret[..8] != SECRET_MAGIC {
        return Err(identity_error(
            "secure identity secret has an invalid header",
        ));
    }
    let node_id: [u8; 16] = secret[8..24]
        .try_into()
        .map_err(|_| identity_error("secure identity Node ID is invalid"))?;
    if node_id == [0; 16] {
        return Err(identity_error("secure identity Node ID must not be zero"));
    }
    let certificate_length = read_length(&secret[24..28])?;
    let key_length = read_length(&secret[28..32])?;
    validate_lengths(certificate_length, key_length)?;
    let expected = 32_usize
        .checked_add(certificate_length)
        .and_then(|length| length.checked_add(key_length))
        .ok_or_else(|| identity_error("secure identity lengths overflow"))?;
    if secret.len() != expected {
        return Err(identity_error(
            "secure identity secret length is inconsistent",
        ));
    }
    let certificate = secret[32..32 + certificate_length].to_vec();
    let key = secret[32 + certificate_length..].to_vec();
    validate_key_pair(&certificate, &key)?;
    Ok(IdentityMaterial {
        node_id,
        certificate_chain: vec![CertificateDer::from(certificate)],
        private_key: PrivatePkcs8KeyDer::from(key).into(),
    })
}

fn validate_key_pair(certificate: &[u8], private_key: &[u8]) -> Result<(), NetToolError> {
    let (remaining, certificate) = x509_parser::parse_x509_certificate(certificate)
        .map_err(|error| identity_error(format!("identity certificate is invalid: {error}")))?;
    if !remaining.is_empty() {
        return Err(identity_error(
            "identity certificate contains trailing data",
        ));
    }
    let key_pair = KeyPair::try_from(private_key)
        .map_err(|error| identity_error(format!("identity private key is invalid: {error}")))?;
    if certificate.public_key().raw != key_pair.subject_public_key_info() {
        return Err(identity_error(
            "identity certificate and private key do not match",
        ));
    }
    Ok(())
}

fn read_length(bytes: &[u8]) -> Result<usize, NetToolError> {
    let value: [u8; 4] = bytes
        .try_into()
        .map_err(|_| identity_error("secure identity length field is invalid"))?;
    Ok(u32::from_be_bytes(value) as usize)
}

fn validate_lengths(certificate: usize, key: usize) -> Result<(), NetToolError> {
    if certificate == 0 || certificate > MAX_CERTIFICATE_BYTES {
        return Err(identity_error("identity certificate length is invalid"));
    }
    if key == 0 || key > MAX_PRIVATE_KEY_BYTES {
        return Err(identity_error("identity private key length is invalid"));
    }
    Ok(())
}

fn validate_subject_names(names: &[String]) -> Result<(), NetToolError> {
    if names.is_empty() || names.len() > 16 {
        return Err(invalid(
            "identity requires between one and sixteen subject names",
        ));
    }
    let mut normalized = names.iter().map(|name| name.trim()).collect::<Vec<_>>();
    if normalized
        .iter()
        .any(|name| name.is_empty() || name.len() > 253)
    {
        return Err(invalid("identity subject name is empty or too long"));
    }
    normalized.sort_unstable();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("identity subject names contain duplicates"));
    }
    Ok(())
}

fn keyring_error(error: &keyring::Error) -> NetToolError {
    identity_error(format!("platform secure identity store failed: {error}"))
}

fn identity_error(message: impl Into<String>) -> NetToolError {
    NetToolError::new(ErrorCode::NodeTlsFailed, message, false)
}

fn invalid(message: &'static str) -> NetToolError {
    NetToolError::new(ErrorCode::InvalidArgument, message, false)
}

#[cfg(test)]
mod tests {
    use super::{IdentityProvider, SecureSecretStore};
    use nettool_error::NetToolError;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MemoryStore {
        secret: RefCell<Option<Vec<u8>>>,
    }

    impl SecureSecretStore for MemoryStore {
        fn get_secret(&self) -> Result<Option<Vec<u8>>, NetToolError> {
            Ok(self.secret.borrow().clone())
        }

        fn set_secret(&self, secret: &[u8]) -> Result<(), NetToolError> {
            *self.secret.borrow_mut() = Some(secret.to_vec());
            Ok(())
        }
    }

    #[test]
    fn creates_and_reloads_stable_secure_identity() {
        let provider = IdentityProvider::new(MemoryStore::default(), vec!["localhost".to_owned()])
            .expect("provider");
        let first = provider.load_or_create().expect("create");
        let second = provider.load_or_create().expect("reload");
        assert_ne!(first.node_id, [0; 16]);
        assert_eq!(first.node_id, second.node_id);
        assert_eq!(
            first.certificate_chain[0].as_ref(),
            second.certificate_chain[0].as_ref()
        );
        assert_eq!(
            first.private_key.secret_der(),
            second.private_key.secret_der()
        );
    }

    #[test]
    fn rejects_corrupted_or_mismatched_secure_secret() {
        let store = MemoryStore::default();
        let provider =
            IdentityProvider::new(store, vec!["localhost".to_owned()]).expect("provider");
        provider.load_or_create().expect("create");
        provider.store.secret.borrow_mut().as_mut().expect("secret")[8..24].fill(0);
        assert!(provider.load_or_create().is_err());
    }

    #[test]
    fn rejects_certificate_and_private_key_mismatch() {
        let first = IdentityProvider::new(MemoryStore::default(), vec!["first.local".to_owned()])
            .expect("first provider");
        let second = IdentityProvider::new(MemoryStore::default(), vec!["second.local".to_owned()])
            .expect("second provider");
        first.load_or_create().expect("first identity");
        second.load_or_create().expect("second identity");
        let second_key = {
            let second_secret = second.store.secret.borrow();
            let second_secret = second_secret.as_ref().expect("second secret");
            let second_certificate_length =
                u32::from_be_bytes(second_secret[24..28].try_into().expect("length")) as usize;
            second_secret[32 + second_certificate_length..].to_vec()
        };
        {
            let mut first_secret = first.store.secret.borrow_mut();
            let first_secret = first_secret.as_mut().expect("first secret");
            let first_certificate_length =
                u32::from_be_bytes(first_secret[24..28].try_into().expect("length")) as usize;
            assert_eq!(
                first_secret.len() - 32 - first_certificate_length,
                second_key.len()
            );
            first_secret[32 + first_certificate_length..].copy_from_slice(&second_key);
        }
        assert!(first.load_or_create().is_err());
    }

    struct FailingStore;

    impl SecureSecretStore for FailingStore {
        fn get_secret(&self) -> Result<Option<Vec<u8>>, NetToolError> {
            Err(NetToolError::new(
                nettool_error::ErrorCode::NodeTlsFailed,
                "secure store locked",
                false,
            ))
        }

        fn set_secret(&self, _secret: &[u8]) -> Result<(), NetToolError> {
            panic!("provider must not attempt a fallback write after read failure")
        }
    }

    #[test]
    fn secure_store_failure_never_falls_back_to_new_identity() {
        let provider =
            IdentityProvider::new(FailingStore, vec!["localhost".to_owned()]).expect("provider");
        assert!(provider.load_or_create().is_err());
    }

    #[test]
    fn rejects_invalid_subject_names_before_storage_access() {
        assert!(IdentityProvider::new(MemoryStore::default(), Vec::new()).is_err());
        assert!(
            IdentityProvider::new(
                MemoryStore::default(),
                vec!["node.local".to_owned(), "node.local".to_owned()]
            )
            .is_err()
        );
    }
}
