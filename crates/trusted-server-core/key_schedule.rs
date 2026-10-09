//! The attestation key schedule a build is given, read into the constant
//! the build script writes.
//!
//! A module of the build script and of the tests in `src/attestation.rs`,
//! which check what a schedule may hold.

/// The source of the `ATTESTATION_KEYS` constant for the text of a key
/// schedule, or of an empty schedule for `None`.
///
/// A schedule holds one key on each line, being the key id, the Unix second
/// the key comes into force and the private key as base64 DER, separated by
/// tabs. Blank lines are passed over.
///
/// A key id and a key may hold only letters, digits and `-_.:+/=`. Each is
/// written into Rust source as a string, so nothing a schedule holds can end
/// the string it is written in.
///
/// # Errors
///
/// Returns the number of the first line of any other shape and what is wrong
/// with it. The line itself is never repeated, because it holds a private
/// key.
pub(crate) fn constant_source(schedule: Option<&str>) -> Result<String, String> {
    let mut source = String::from("const ATTESTATION_KEYS: &[(&str, i64, &str)] = &[");
    for (index, line) in schedule.unwrap_or_default().lines().enumerate() {
        let line = line.trim_matches([' ', '\r']);
        if line.is_empty() {
            continue;
        }
        let number = index + 1;
        let fields: Vec<&str> = line.split('\t').collect();
        let [key_id, starts_at, private_key] = fields.as_slice() else {
            return Err(format!(
                "line {number} should hold a key id, a start and a key, separated by tabs"
            ));
        };
        let starts_at: i64 = starts_at
            .parse()
            .map_err(|_| format!("line {number} should give the key's start as Unix seconds"))?;
        if !is_plain(key_id) || !is_plain(private_key) {
            return Err(format!(
                "line {number} should hold a key id and a key of letters, digits and -_.:+/= only"
            ));
        }
        source.push_str(&format!("({key_id:?}, {starts_at}, {private_key:?}),"));
    }
    source.push_str("];");
    Ok(source)
}

/// Whether a schedule field holds only characters a key id or base64 uses.
fn is_plain(field: &str) -> bool {
    !field.is_empty()
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:+/=".contains(&b))
}
