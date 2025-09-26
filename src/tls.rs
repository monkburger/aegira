use std::{collections::HashMap, fmt, fs, io::BufReader, sync::{Arc, Mutex}};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};
use anyhow::{Context, Result};
use quinn::{crypto::rustls::QuicServerConfig, ServerConfig as QuinnServerConfig};
use rand::RngCore;
use rustls::{
    crypto::aws_lc_rs::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ProducesTickets, ResolvesServerCert, ServerConfig},
    sign::CertifiedKey,
};
use rustls_pemfile::{certs, private_key};

use crate::config::{Config, SniPolicy, Tls};

// ---------------------------------------------------------------------------
// Session ticket key rotation (RFC 8446 S4.6.3)
// ---------------------------------------------------------------------------
//
// TLS 1.3 session tickets are encrypted under a symmetric key.  A static
// key means that compromise of the key at any point retroactively exposes
// every recorded session (a violation of forward secrecy at the ticket
// layer, distinct from the ephemeral DH key exchange).
//
// RotatingTicketEncrypter maintains two key slots: `current` and
// `previous`.  On rotation, `current` is demoted to `previous` and a
// fresh key takes its place.  Decrypt tries `current` first (common
// case), then `previous` (tickets minted just before the rotation).
// Clients therefore get a one-interval grace window for resumption.

struct TicketKeys {
    current: ([u8; 32], Aes256Gcm),
    previous: Option<([u8; 32], Aes256Gcm)>,
}

/// AES-256-GCM session ticket encrypter with periodic key rotation.
pub struct RotatingTicketEncrypter {
    state: Mutex<TicketKeys>,
    /// Lifetime reported to TLS clients (seconds), per RFC 8446 S4.6.1.
    lifetime: u32,
}

impl fmt::Debug for RotatingTicketEncrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RotatingTicketEncrypter")
    }
}

fn generate_aes_key() -> ([u8; 32], Aes256Gcm) {
    let mut key_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    (key_bytes, cipher)
}

impl RotatingTicketEncrypter {
    /// Initialise with a freshly generated key.
    pub fn new(lifetime: u32) -> Self {
        Self {
            state: Mutex::new(TicketKeys {
                current: generate_aes_key(),
                previous: None,
            }),
            lifetime,
        }
    }

    /// Rotate to a fresh key.  The outgoing key is kept for one interval
    /// so tickets minted immediately before the cutover still decrypt.
    pub fn rotate(&self) {
        let fresh = generate_aes_key();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let old_current = std::mem::replace(&mut state.current, fresh);
        state.previous = Some(old_current);
    }
}

impl ProducesTickets for RotatingTicketEncrypter {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime
    }

    fn encrypt(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Fresh random nonce per ticket (RFC 8446 S5.5).
        let nonce = Aes256Gcm::generate_nonce(&mut rand::thread_rng());

        let state = self.state.lock().ok()?;
        let mut ciphertext = state.current.1.encrypt(&nonce, message).ok()?;

        // Layout: 12-byte nonce || ciphertext || GCM tag
        let mut output = nonce.to_vec();
        output.append(&mut ciphertext);
        Some(output)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        const NONCE_LEN: usize = 12;
        if ciphertext.len() <= NONCE_LEN {
            return None;
        }
        // aes_gcm::aead::Nonce<C> = GenericArray<u8, C::NonceSize> — resolves to U12.
        let nonce =
            aes_gcm::aead::Nonce::<Aes256Gcm>::from_slice(&ciphertext[..NONCE_LEN]);
        let ct = &ciphertext[NONCE_LEN..];

        let state = self.state.lock().ok()?;
        // Try the current key first (fast path).
        if let Ok(plain) = state.current.1.decrypt(nonce, ct) {
            return Some(plain);
        }
        // Grace path: try the pre-rotation key.
        if let Some((_, ref prev_cipher)) = state.previous {
            if let Ok(plain) = prev_cipher.decrypt(nonce, ct) {
                return Some(plain);
            }
        }
        None
    }
}

#[derive(Debug)]
struct PolicyCertResolver {
    by_name: HashMap<String, Arc<CertifiedKey>>,
    default_cert: Arc<CertifiedKey>,
    reject_unknown_sni: bool,
    reject_missing_sni: bool,
}

impl ResolvesServerCert for PolicyCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        match client_hello.server_name() {
            Some(name) => {
                let key = name.to_ascii_lowercase();
                if let Some(cert) = self.by_name.get(&key) {
                    return Some(Arc::clone(cert));
                }
                if self.reject_unknown_sni {
                    None
                } else {
                    Some(Arc::clone(&self.default_cert))
                }
            }
            None => {
                if self.reject_missing_sni {
                    None
                } else {
                    Some(Arc::clone(&self.default_cert))
                }
            }
        }
    }
}

/// Load a PEM certificate chain.
fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let data = fs::read(path).with_context(|| format!("read certificate file {path}"))?;
    let mut reader = BufReader::new(data.as_slice());
    let chain: Vec<CertificateDer<'static>> = certs(&mut reader)
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("decode certificates from {path}"))?;
    if chain.is_empty() {
        anyhow::bail!("no certificates found in {path}");
    }
    Ok(chain)
}

/// Load a PEM private key.
fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let data = fs::read(path).with_context(|| format!("read private key file {path}"))?;
    let mut reader = BufReader::new(data.as_slice());
    private_key(&mut reader)
        .with_context(|| format!("decode private key from {path}"))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {path}"))
}

/// Construct a `CertifiedKey` from PEM cert and key files.
fn load_certified_key(
    cert_path: &str,
    key_path: &str,
) -> Result<CertifiedKey> {
    let chain = load_certs(cert_path)?;
    let key_der = load_private_key(key_path)?;
    let signing_key = any_supported_type(&key_der)
        .with_context(|| format!("create signing key from {key_path}"))?;
    Ok(CertifiedKey::new(chain, signing_key))
}

fn build_server_config_with_alpn(
    config: &Config,
    alpn_protocols: &[&[u8]],
    ticket_encrypter: Option<&Arc<RotatingTicketEncrypter>>,
) -> Result<Option<Arc<ServerConfig>>> {
    if !config.tls.enabled {
        return Ok(None);
    }

    let tls: &Tls = &config.tls;

    // Load the default cert/key pair.  Also serves as fallback for
    // sites that do not override their cert paths.
    let default_ck = load_certified_key(
        &tls.default_certificate,
        &tls.default_private_key,
    )
    .context("load default TLS certificate/key")?;
    let default_ck = Arc::new(default_ck);

    let reject_unknown_sni = tls.unknown_sni == SniPolicy::Reject;
    let reject_missing_sni = tls.missing_sni == SniPolicy::Reject;
    let mut by_name: HashMap<String, Arc<CertifiedKey>> = HashMap::new();

    for site in &config.sites {
        let cert_path = if !site.certificate.is_empty() {
            site.certificate.as_str()
        } else {
            tls.default_certificate.as_str()
        };
        let key_path = if !site.private_key.is_empty() {
            site.private_key.as_str()
        } else {
            tls.default_private_key.as_str()
        };
        let same_as_default = cert_path == tls.default_certificate
            && key_path == tls.default_private_key;

        let ck = if same_as_default {
            Arc::clone(&default_ck)
        } else {
            Arc::new(
                load_certified_key(cert_path, key_path).with_context(|| {
                    format!("load TLS certificate for site {}", site.server_name)
                })?,
            )
        };

        by_name.insert(site.server_name.to_ascii_lowercase(), Arc::clone(&ck));
    }

    if by_name.is_empty() {
        anyhow::bail!("no TLS sites available for SNI certificate resolution");
    }

    let resolver = PolicyCertResolver {
        by_name,
        default_cert: Arc::clone(&default_ck),
        reject_unknown_sni,
        reject_missing_sni,
    };

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    server_config.alpn_protocols = alpn_protocols.iter().map(|v| v.to_vec()).collect();

    // Attach the rotating ticket encrypter if configured.
    if let Some(enc) = ticket_encrypter {
        server_config.ticketer = Arc::clone(enc) as Arc<dyn ProducesTickets>;
    }

    Ok(Some(Arc::new(server_config)))
}

/// Build a [`ServerConfig`] for the TCP+TLS frontend.
pub fn build_server_config(
    config: &Config,
    ticket_encrypter: Option<&Arc<RotatingTicketEncrypter>>,
) -> Result<Option<Arc<ServerConfig>>> {
    let mut alpn = Vec::new();
    if config.listener.serve_http2 {
        alpn.push(b"h2".as_slice());
    }
    if config.listener.serve_http1 || alpn.is_empty() {
        alpn.push(b"http/1.1".as_slice());
    }
    build_server_config_with_alpn(config, &alpn, ticket_encrypter)
}

/// Build a QUIC server config for HTTP/3.
pub fn build_quic_server_config(
    config: &Config,
    ticket_encrypter: Option<&Arc<RotatingTicketEncrypter>>,
) -> Result<Option<QuinnServerConfig>> {
    let Some(server_config) =
        build_server_config_with_alpn(config, &[b"h3"], ticket_encrypter)?
    else {
        return Ok(None);
    };

    let quic_server_config = QuinnServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(
        (*server_config).clone(),
    )?));

    Ok(Some(quic_server_config))
}
