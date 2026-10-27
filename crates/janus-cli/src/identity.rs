//! Identity files and fingerprints.
//!
//! Two formats, both created with mode 0600 on Unix and never overwritten:
//!
//! **v1 (plaintext)** — the 64-byte seed in hex. Convenient for demos only.
//!
//! ```text
//! # janus identity v1 - SECRET KEY MATERIAL, do not share
//! <128 hex chars>
//! ```
//!
//! **v2 (encrypted)** — the seed sealed with XChaCha20-Poly1305 under a key
//! derived from a passphrase with Argon2id (RFC 9106):
//!
//! ```text
//! # janus identity v2 - encrypted secret key, do not share
//! janus-identity-v2 argon2id-v19 m=65536 t=3 p=1
//! salt <16 bytes hex>
//! nonce <24 bytes hex>
//! sealed <80 bytes hex>
//! ```
//!
//! The parameter line is the AEAD's associated data, so changing it (to
//! weaken the KDF, say) makes decryption fail. When reading, the parameters
//! are also bounded, so a hostile file cannot make us allocate gigabytes.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead as _, Payload};
use chacha20poly1305::{KeyInit as _, XChaCha20Poly1305, XNonce};
use janus_core::sig::{FINGERPRINT_LEN, Fingerprint, IDENTITY_SEED_LEN, IdentityKeypair};
use rand_core::{TryRng as _, UnwrapErr};
use zeroize::Zeroizing;

const HEADER_V1: &str = "# janus identity v1 - SECRET KEY MATERIAL, do not share";
const HEADER_V2: &str = "# janus identity v2 - encrypted secret key, do not share";
const MAGIC_V2: &str = "janus-identity-v2";

/// Argon2id parameters for new files: 64 MiB, 3 passes (RFC 9106, §4,
/// second recommended option, with one lane).
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
/// Bounds accepted when reading.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;
const MAX_P_COST: u32 = 8;

/// Shortest passphrase accepted for new files.
pub const MIN_PASSPHRASE_LEN: usize = 8;

/// A passphrase, wiped from memory on drop.
pub type Passphrase = Zeroizing<String>;

fn create_private(path: &Path) -> Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
        .with_context(|| format!("cannot create {} (already exists?)", path.display()))
}

fn derive_key(pass: &str, salt: &[u8], m: u32, t: u32, p: u32) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(m, t, p, Some(32)).map_err(|e| anyhow!("argon2 parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn params_line(m: u32, t: u32, p: u32) -> String {
    format!("{MAGIC_V2} argon2id-v19 m={m} t={t} p={p}")
}

/// Write a new identity to `path`, encrypted if a passphrase is given.
/// Refuses to overwrite an existing file.
pub fn save(path: &Path, id: &IdentityKeypair, passphrase: Option<&Passphrase>) -> Result<()> {
    let seed = id.to_seed();
    let body = match passphrase {
        None => Zeroizing::new(format!("{HEADER_V1}\n{}\n", hex::encode(seed.as_slice()))),
        Some(pass) => {
            ensure!(
                pass.chars().count() >= MIN_PASSPHRASE_LEN,
                "passphrase too short (at least {MIN_PASSPHRASE_LEN} characters)"
            );
            let mut rng = UnwrapErr(getrandom::SysRng);
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 24];
            rng.try_fill_bytes(&mut salt)
                .and_then(|()| rng.try_fill_bytes(&mut nonce))
                .map_err(|_| anyhow!("OS RNG failure"))?;
            let key = derive_key(pass, &salt, M_COST_KIB, T_COST, P_COST)?;
            let line = params_line(M_COST_KIB, T_COST, P_COST);
            let sealed = XChaCha20Poly1305::new_from_slice(key.as_slice())
                .map_err(|_| anyhow!("key length"))?
                .encrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: seed.as_slice(),
                        aad: line.as_bytes(),
                    },
                )
                .map_err(|_| anyhow!("encryption failed"))?;
            Zeroizing::new(format!(
                "{HEADER_V2}\n{line}\nsalt {}\nnonce {}\nsealed {}\n",
                hex::encode(salt),
                hex::encode(nonce),
                hex::encode(sealed)
            ))
        }
    };
    create_private(path)?.write_all(body.as_bytes())?;
    Ok(())
}

/// Whether the identity file at `path` is passphrase-protected.
pub fn is_encrypted(path: &Path) -> Result<bool> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    Ok(text.lines().any(|l| l.starts_with(MAGIC_V2)))
}

/// Load an identity. `passphrase` is called only for encrypted files.
pub fn load(
    path: &Path,
    passphrase: impl FnOnce() -> Result<Passphrase>,
) -> Result<IdentityKeypair> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'));
    let Some(first) = lines.next() else {
        bail!("{}: no key material found", path.display());
    };
    let mut seed = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
    if !first.starts_with(MAGIC_V2) {
        hex::decode_to_slice(first, seed.as_mut_slice())
            .with_context(|| format!("{}: invalid identity encoding", path.display()))?;
        return Ok(IdentityKeypair::from_seed(&seed));
    }

    let bad = || anyhow!("{}: malformed encrypted identity", path.display());
    let (m, t, p) = parse_params(first).ok_or_else(bad)?;
    ensure!(
        (8..=MAX_M_COST_KIB).contains(&m)
            && (1..=MAX_T_COST).contains(&t)
            && (1..=MAX_P_COST).contains(&p),
        "{}: Argon2 parameters out of the accepted range",
        path.display()
    );
    let mut field = |name: &str| -> Result<Vec<u8>> {
        let line = lines.next().ok_or_else(bad)?;
        let value = line
            .strip_prefix(name)
            .and_then(|v| v.strip_prefix(' '))
            .ok_or_else(bad)?;
        hex::decode(value).map_err(|_| bad())
    };
    let salt = field("salt")?;
    let nonce: [u8; 24] = field("nonce")?.try_into().map_err(|_| bad())?;
    let sealed = field("sealed")?;

    let pass = passphrase()?;
    let key = derive_key(&pass, &salt, m, t, p)?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key.as_slice())
            .map_err(|_| anyhow!("key length"))?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &sealed,
                    aad: first.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("{}: wrong passphrase or corrupted file", path.display()))?,
    );
    ensure!(plain.len() == IDENTITY_SEED_LEN, bad());
    seed.copy_from_slice(&plain);
    Ok(IdentityKeypair::from_seed(&seed))
}

fn parse_params(line: &str) -> Option<(u32, u32, u32)> {
    let mut it = line.split(' ');
    if it.next()? != MAGIC_V2 || it.next()? != "argon2id-v19" {
        return None;
    }
    let mut get = |k: &str| it.next()?.strip_prefix(k)?.parse::<u32>().ok();
    let (m, t, p) = (get("m=")?, get("t=")?, get("p=")?);
    it.next().is_none().then_some((m, t, p))
}

/// Parse a hex fingerprint (as printed by `janus keygen` / `fingerprint`).
pub fn parse_fingerprint(s: &str) -> Result<Fingerprint> {
    let mut fp = [0u8; FINGERPRINT_LEN];
    hex::decode_to_slice(s.trim(), &mut fp).with_context(|| {
        format!(
            "invalid fingerprint {s:?} (expected {} hex chars)",
            2 * FINGERPRINT_LEN
        )
    })?;
    Ok(Fingerprint(fp))
}

/// Load fingerprints, one per line (`#` comments allowed).
pub fn load_trust_file(path: &Path) -> Result<Vec<Fingerprint>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    text.lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| !l.is_empty())
        .map(parse_fingerprint)
        .collect()
}

/// Group a hex string for easier human comparison: `a1b2 c3d4 …`.
pub fn grouped(bytes: &[u8]) -> String {
    let hex = hex::encode(bytes);
    let mut out = String::with_capacity(hex.len().saturating_mul(5) / 4);
    for (i, c) in hex.chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("janus-id-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        let _ = fs::remove_file(&p);
        p
    }

    fn pass(s: &str) -> impl FnOnce() -> Result<Passphrase> {
        let s = s.to_owned();
        move || Ok(Zeroizing::new(s))
    }

    fn never() -> impl FnOnce() -> Result<Passphrase> {
        || panic!("passphrase requested for a plaintext file")
    }

    #[test]
    fn plaintext_roundtrip_and_no_overwrite() {
        let path = tmp("plain.id");
        let id = IdentityKeypair::from_seed(&[5; 64]);
        save(&path, &id, None).unwrap();
        assert!(!is_encrypted(&path).unwrap());
        assert_eq!(load(&path, never()).unwrap().public(), id.public());
        assert!(
            save(&path, &id, None).is_err(),
            "must not overwrite an identity"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn encrypted_roundtrip() {
        let path = tmp("enc.id");
        let id = IdentityKeypair::from_seed(&[6; 64]);
        save(
            &path,
            &id,
            Some(&Zeroizing::new("correct horse battery".into())),
        )
        .unwrap();
        assert!(is_encrypted(&path).unwrap());
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains(&hex::encode(id.to_seed().as_slice())),
            "seed leaked"
        );
        assert_eq!(
            load(&path, pass("correct horse battery")).unwrap().public(),
            id.public()
        );
        let err = load(&path, pass("wrong horse battery")).unwrap_err();
        assert!(format!("{err}").contains("wrong passphrase"), "{err}");
    }

    #[test]
    fn tampered_parameters_are_rejected() {
        let path = tmp("tamper.id");
        let id = IdentityKeypair::from_seed(&[7; 64]);
        save(
            &path,
            &id,
            Some(&Zeroizing::new("correct horse battery".into())),
        )
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        // Downgrade the KDF cost: authenticated as AAD, so decryption fails.
        let weak = text.replace("t=3", "t=1");
        let p2 = tmp("tamper2.id");
        fs::write(&p2, weak).unwrap();
        assert!(load(&p2, pass("correct horse battery")).is_err());
        // Absurd memory cost: refused before any allocation.
        let huge = text.replace("m=65536", "m=4000000000");
        let p3 = tmp("tamper3.id");
        fs::write(&p3, huge).unwrap();
        let err = load(&p3, never()).unwrap_err();
        assert!(
            format!("{err}").contains("out of the accepted range"),
            "{err}"
        );
    }

    #[test]
    fn short_passphrase_is_refused() {
        let path = tmp("short.id");
        let id = IdentityKeypair::from_seed(&[8; 64]);
        assert!(save(&path, &id, Some(&Zeroizing::new("short".into()))).is_err());
    }

    #[test]
    fn fingerprint_parsing() {
        let fp = IdentityKeypair::from_seed(&[5; 64]).public().fingerprint();
        assert_eq!(parse_fingerprint(&fp.to_string()).unwrap(), fp);
        assert!(parse_fingerprint("abcd").is_err());
    }
}
