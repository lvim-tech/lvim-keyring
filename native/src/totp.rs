// lvim-keyring-native/totp: RFC 6238 time-based one-time passwords.
//
// A TOTP entry stores a base32 SECRET (the "key" a site shows when enabling 2FA); the current 6-digit
// code is HMAC-SHA1(secret, floor(unix_time / period)) run through the standard dynamic-truncation.
// The secret never leaves the daemon — the code is computed here and only the 6 digits cross to Lua.

use anyhow::{anyhow, Result};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// The current TOTP code for `secret_b32` at `unix_time`, with `period`-second steps and `digits`
/// digits (RFC 6238 defaults: 30s, 6 digits). Case- and whitespace-insensitive base32; padding ok.
pub fn code(secret_b32: &str, unix_time: u64, period: u64, digits: u32) -> Result<String> {
    if period == 0 || !(1..=9).contains(&digits) {
        return Err(anyhow!("invalid TOTP parameters"));
    }
    // Normalize the secret: strip spaces + padding, upper-case (base32 alphabet).
    let cleaned: String = secret_b32
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .flat_map(char::to_uppercase)
        .collect();
    let key = BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|_| anyhow!("not a valid base32 TOTP secret"))?;

    let counter = (unix_time / period).to_be_bytes();
    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| anyhow!("invalid TOTP secret length"))?;
    mac.update(&counter);
    let hs = mac.finalize().into_bytes();

    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (hs[hs.len() - 1] & 0x0f) as usize;
    let bin = ((hs[offset] as u32 & 0x7f) << 24)
        | ((hs[offset + 1] as u32) << 16)
        | ((hs[offset + 2] as u32) << 8)
        | (hs[offset + 3] as u32);
    let modulo = 10u32.pow(digits);
    Ok(format!("{:0width$}", bin % modulo, width = digits as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 test vector: ASCII secret "12345678901234567890" = base32 GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
    #[test]
    fn rfc6238_vector() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        // At T=59s, counter=1, the RFC's SHA1 8-digit code is 94287082 → 6 digits = 287082.
        assert_eq!(code(secret, 59, 30, 6).unwrap(), "287082");
        // At T=1111111109, the RFC 8-digit code is 07081804 → 6 digits = 081804.
        assert_eq!(code(secret, 1111111109, 30, 6).unwrap(), "081804");
    }

    #[test]
    fn lowercase_and_spaces_ok() {
        let a = code("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59, 30, 6).unwrap();
        assert_eq!(a, "287082");
    }

    #[test]
    fn bad_secret_errors() {
        assert!(code("not!base32!", 0, 30, 6).is_err());
    }
}
