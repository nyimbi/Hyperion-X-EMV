use crate::error::{KernelError, KernelResult};
use core::fmt::Write;

pub const MAX_PROVENANCE_ARTIFACTS: usize = 64;
pub const MAX_PROVENANCE_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Artifact<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDigest {
    pub name: String,
    pub len: usize,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildProvenance {
    pub kernel_name: &'static str,
    pub kernel_version: &'static str,
    pub abi_version: u32,
    pub artifacts: Vec<ArtifactDigest>,
}

impl BuildProvenance {
    pub fn canonical_json(&self) -> String {
        let mut out = String::new();
        out.push('{');
        push_json_str(&mut out, "type", "build-provenance");
        out.push(',');
        push_json_str(&mut out, "kernel_name", self.kernel_name);
        out.push(',');
        push_json_str(&mut out, "kernel_version", self.kernel_version);
        out.push(',');
        push_json_number(&mut out, "abi_version", self.abi_version as u64);
        out.push_str(",\"artifacts\":[");
        for (idx, artifact) in self.artifacts.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            out.push('{');
            push_json_str(&mut out, "name", &artifact.name);
            out.push(',');
            push_json_number(&mut out, "len", artifact.len as u64);
            out.push(',');
            push_json_str(&mut out, "sha256", &to_hex(&artifact.sha256));
            out.push('}');
        }
        out.push_str("]}");
        out
    }
}

pub fn build_provenance_manifest(
    abi_version: u32,
    artifacts: &[Artifact<'_>],
) -> KernelResult<BuildProvenance> {
    if artifacts.is_empty() || artifacts.len() > MAX_PROVENANCE_ARTIFACTS {
        return Err(KernelError::LengthOverflow);
    }

    let mut digests = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        validate_artifact(artifact)?;
        digests.push(ArtifactDigest {
            name: artifact.name.to_string(),
            len: artifact.bytes.len(),
            sha256: sha256(artifact.bytes),
        });
    }
    digests.sort_by(|left, right| left.name.cmp(&right.name));
    for pair in digests.windows(2) {
        if pair[0].name == pair[1].name {
            return Err(KernelError::InvalidArgument);
        }
    }

    Ok(BuildProvenance {
        kernel_name: env!("CARGO_PKG_NAME"),
        kernel_version: env!("CARGO_PKG_VERSION"),
        abi_version,
        artifacts: digests,
    })
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h = H0;
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        compress(&mut h, chunk, &K);
    }

    let remainder = chunks.remainder();
    let mut final_blocks = [[0u8; 64]; 2];
    final_blocks[0][..remainder.len()].copy_from_slice(remainder);
    final_blocks[0][remainder.len()] = 0x80;
    let final_count = if remainder.len() <= 55 {
        final_blocks[0][56..64].copy_from_slice(&bit_len.to_be_bytes());
        1
    } else {
        final_blocks[1][56..64].copy_from_slice(&bit_len.to_be_bytes());
        2
    };
    for block in final_blocks.iter().take(final_count) {
        compress(&mut h, block, &K);
    }

    let mut out = [0u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn validate_artifact(artifact: &Artifact<'_>) -> KernelResult<()> {
    if artifact.name.is_empty()
        || artifact.name.len() > 256
        || artifact.bytes.is_empty()
        || artifact.bytes.len() > MAX_PROVENANCE_ARTIFACT_BYTES
        || artifact.name.bytes().any(|byte| {
            !matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' | b'/')
        })
    {
        return Err(KernelError::InvalidArgument);
    }
    Ok(())
}

fn compress(h: &mut [u32; 8], chunk: &[u8], k: &[u32; 64]) {
    let mut w = [0u32; 64];
    for (idx, word) in w.iter_mut().take(16).enumerate() {
        let offset = idx * 4;
        *word = u32::from_be_bytes([
            chunk[offset],
            chunk[offset + 1],
            chunk[offset + 2],
            chunk[offset + 3],
        ]);
    }
    for idx in 16..64 {
        let s0 = w[idx - 15].rotate_right(7) ^ w[idx - 15].rotate_right(18) ^ (w[idx - 15] >> 3);
        let s1 = w[idx - 2].rotate_right(17) ^ w[idx - 2].rotate_right(19) ^ (w[idx - 2] >> 10);
        w[idx] = w[idx - 16]
            .wrapping_add(s0)
            .wrapping_add(w[idx - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut hh = h[7];

    for idx in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[idx])
            .wrapping_add(w[idx]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

fn push_json_str(out: &mut String, key: &str, value: &str) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn push_json_number(out: &mut String, key: &str, value: u64) {
    out.push('"');
    out.push_str(key);
    out.push_str("\":");
    let _ = write!(out, "{value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_standard_vectors() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn provenance_manifest_is_canonical_and_rejects_duplicates() {
        let manifest = build_provenance_manifest(
            1,
            &[
                Artifact {
                    name: "docs/spec.md",
                    bytes: b"spec",
                },
                Artifact {
                    name: "Cargo.lock",
                    bytes: b"lock",
                },
            ],
        )
        .unwrap();
        assert_eq!(manifest.artifacts[0].name, "Cargo.lock");
        assert_eq!(manifest.artifacts[1].name, "docs/spec.md");
        let json = manifest.canonical_json();
        assert!(json.contains("\"type\":\"build-provenance\""));
        assert!(json.contains("\"kernel_name\":\"hyperion-emv\""));
        assert!(json.contains("\"name\":\"Cargo.lock\""));
        assert!(json.contains("\"sha256\":\""));

        assert_eq!(
            build_provenance_manifest(
                1,
                &[
                    Artifact {
                        name: "Cargo.lock",
                        bytes: b"lock",
                    },
                    Artifact {
                        name: "Cargo.lock",
                        bytes: b"lock2",
                    },
                ],
            )
            .unwrap_err(),
            KernelError::InvalidArgument
        );
    }

    #[test]
    fn provenance_manifest_rejects_resource_limits() {
        assert_eq!(
            build_provenance_manifest(1, &[]).unwrap_err(),
            KernelError::LengthOverflow
        );

        let names = (0..=MAX_PROVENANCE_ARTIFACTS)
            .map(|index| format!("artifact_{index}.bin"))
            .collect::<Vec<_>>();
        let artifacts = names
            .iter()
            .map(|name| Artifact {
                name: name.as_str(),
                bytes: b"x",
            })
            .collect::<Vec<_>>();

        assert_eq!(
            build_provenance_manifest(1, &artifacts).unwrap_err(),
            KernelError::LengthOverflow
        );
    }
}
