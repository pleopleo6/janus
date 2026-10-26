//! Identity files and fingerprints.
//!
//! An identity file holds the 64-byte secret seed in hex. It is **not
//! encrypted**: this is a demo. On Unix it is created with mode 0600.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context, Result, bail};
use janus_core::sig::{FINGERPRINT_LEN, Fingerprint, IDENTITY_SEED_LEN, IdentityKeypair};
use zeroize::Zeroizing;

const HEADER: &str = "# janus identity v1 - SECRET KEY MATERIAL, do not share";

/// Write a freshly generated identity to `path` (refuses to overwrite).
pub fn save(path: &Path, id: &IdentityKeypair) -> Result<()> {
    let seed = id.to_seed();
    let body = Zeroizing::new(format!("{HEADER}\n{}\n", hex::encode(seed.as_slice())));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("cannot create {} (already exists?)", path.display()))?;
    f.write_all(body.as_bytes())?;
    Ok(())
}

/// Load an identity from `path`.
pub fn load(path: &Path) -> Result<IdentityKeypair> {
    let text = Zeroizing::new(
        fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?,
    );
    let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    else {
        bail!("{}: no key material found", path.display());
    };
    let mut seed = Zeroizing::new([0u8; IDENTITY_SEED_LEN]);
    hex::decode_to_slice(line, seed.as_mut_slice())
        .with_context(|| format!("{}: invalid identity encoding", path.display()))?;
    Ok(IdentityKeypair::from_seed(&seed))
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip_and_no_overwrite() {
        let dir = std::env::temp_dir().join(format!("janus-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.id");
        let _ = fs::remove_file(&path);
        let id = IdentityKeypair::from_seed(&[5; 64]);
        save(&path, &id).unwrap();
        assert_eq!(load(&path).unwrap().public(), id.public());
        assert!(save(&path, &id).is_err(), "must not overwrite an identity");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn fingerprint_parsing() {
        let fp = IdentityKeypair::from_seed(&[5; 64]).public().fingerprint();
        assert_eq!(parse_fingerprint(&fp.to_string()).unwrap(), fp);
        assert!(parse_fingerprint("abcd").is_err());
    }
}
