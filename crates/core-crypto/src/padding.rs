use crate::CryptoError;

/// Fixed padding size classes (in bytes) to reduce bandwidth compared to flat 4 KiB padding
/// while hiding exact byte length within each bucket.
pub const PADDING_CLASSES: [usize; 4] = [128, 512, 2048, 8192];

/// Maximum plaintext bytes that fit inside the largest padding class (2-byte length prefix).
pub const MAX_PLAINTEXT_BYTES: usize = 8192 - 2;

/// Pads `plaintext` into the smallest fixed padding class that fits `2 + plaintext.len()`.
/// Format: `[len_hi, len_lo, plaintext..., 0x00...]`.
pub fn pad_payload(plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(CryptoError::PaddingError(format!(
            "plaintext exceeds max size ({} > {})",
            plaintext.len(),
            MAX_PLAINTEXT_BYTES
        )));
    }
    let needed = plaintext.len() + 2;
    let target_len = PADDING_CLASSES
        .iter()
        .copied()
        .find(|&bucket| bucket >= needed)
        .ok_or_else(|| CryptoError::PaddingError("no padding bucket fits payload".into()))?;

    let mut out = vec![0u8; target_len];
    let len_bytes = (plaintext.len() as u16).to_be_bytes();
    out[0] = len_bytes[0];
    out[1] = len_bytes[1];
    out[2..2 + plaintext.len()].copy_from_slice(plaintext);
    Ok(out)
}

/// Removes padding from a bucketed payload and verifies structural integrity.
pub fn unpad_payload(padded: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if !PADDING_CLASSES.contains(&padded.len()) {
        return Err(CryptoError::PaddingError(format!(
            "invalid padded length {}",
            padded.len()
        )));
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if 2 + len > padded.len() {
        return Err(CryptoError::PaddingError(
            "declared length exceeds padded buffer".into(),
        ));
    }
    if padded[2 + len..].iter().any(|&b| b != 0) {
        return Err(CryptoError::PaddingError(
            "non-zero trailing padding bytes".into(),
        ));
    }
    Ok(padded[2..2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_into_expected_buckets_and_roundtrips() {
        let small = pad_payload(b"hello").unwrap();
        assert_eq!(small.len(), 128);
        assert_eq!(unpad_payload(&small).unwrap(), b"hello");

        let medium = pad_payload(&[b'a'; 200]).unwrap();
        assert_eq!(medium.len(), 512);
        assert_eq!(unpad_payload(&medium).unwrap(), vec![b'a'; 200]);

        let large = pad_payload(&[b'b'; 1500]).unwrap();
        assert_eq!(large.len(), 2048);
        assert_eq!(unpad_payload(&large).unwrap(), vec![b'b'; 1500]);

        let xlarge = pad_payload(&[b'c'; 4000]).unwrap();
        assert_eq!(xlarge.len(), 8192);
        assert_eq!(unpad_payload(&xlarge).unwrap(), vec![b'c'; 4000]);
    }

    #[test]
    fn rejects_oversize_and_corrupted_padding() {
        assert!(pad_payload(&[0u8; MAX_PLAINTEXT_BYTES + 1]).is_err());

        let mut tampered = pad_payload(b"test").unwrap();
        let last = tampered.len() - 1;
        tampered[last] = 1;
        assert!(unpad_payload(&tampered).is_err());
    }
}
