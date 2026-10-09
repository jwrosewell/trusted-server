use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use edgezero_core::manifest::ManifestLoader;

mod build_time;

/// Source file that must stay out of the generated list.
///
/// `migration_guards.rs` holds the banned pattern itself, as the regex literal
/// the guard matches with, so including it would fail the guard on its own
/// text.
const EXCLUDED: &str = "migration_guards.rs";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    write_default_config_store_id();
    write_migration_guard_sources();
    write_build_time();
    write_build_identity();
    write_attestation_keys();
}

/// Embeds the attestation signing key schedule in the file
/// `TRUSTED_SERVER_ATTESTATION_KEYS` names, or an empty schedule.
///
/// One key per line, being the key id, the Unix second it comes into force
/// and the private key as base64 DER, separated by tabs. The schedule is
/// compiled into the binary, so no signing key sits in a store the service
/// reads when it runs.
fn write_attestation_keys() {
    println!("cargo:rerun-if-env-changed=TRUSTED_SERVER_ATTESTATION_KEYS");
    let mut generated = String::from("const ATTESTATION_KEYS: &[(&str, i64, &str)] = &[");
    if let Some(path) =
        env::var_os("TRUSTED_SERVER_ATTESTATION_KEYS").filter(|path| !path.is_empty())
    {
        let path = PathBuf::from(path);
        println!("cargo:rerun-if-changed={}", path.display());
        let text = fs::read_to_string(&path).expect("should read the attestation key schedule");
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let mut fields = line.split('\t');
            let key_id = fields.next().unwrap_or_default();
            let starts_at: i64 = fields
                .next()
                .unwrap_or_default()
                .parse()
                .expect("should read each attestation key's start as Unix seconds");
            let private_key = fields.next().unwrap_or_default();
            assert!(
                fields.next().is_none() && is_plain(key_id) && is_plain(private_key),
                "each attestation key line should hold a key id, a start and a key",
            );
            generated.push_str(&format!("({key_id:?}, {starts_at}, {private_key:?}),"));
        }
    }
    generated.push_str("];");
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("should read OUT_DIR"));
    fs::write(out_dir.join("attestation_keys.rs"), generated)
        .expect("should write the attestation key schedule");
}

/// Whether a schedule field holds only characters a key id or base64 uses.
fn is_plain(field: &str) -> bool {
    !field.is_empty()
        && field
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:+/=".contains(&b))
}

/// Bakes the build time into the binary as `TRUSTED_SERVER_BUILT_AT`.
///
/// Some hosts give a WebAssembly guest no custom environment variable when it
/// runs, so the time a build was made has to be in the binary or it cannot be
/// reported at all.
///
/// `SOURCE_DATE_EPOCH` is honored where it is set, so a reproducible build
/// stays reproducible rather than differing only by this string.
fn write_build_time() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let seconds = env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| i64::try_from(elapsed.as_secs()).unwrap_or_default())
                .unwrap_or_default()
        });
    println!(
        "cargo:rustc-env=TRUSTED_SERVER_BUILT_AT={}",
        build_time::rfc3339_utc(seconds)
    );
}

/// Bakes in the commit and the build run the builder names, as
/// `TRUSTED_SERVER_COMMIT` and `TRUSTED_SERVER_BUILD_RUN`, or `unknown`.
fn write_build_identity() {
    for name in ["TRUSTED_SERVER_COMMIT", "TRUSTED_SERVER_BUILD_RUN"] {
        println!("cargo:rerun-if-env-changed={name}");
        let value = env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .unwrap_or_else(|| "unknown".to_owned());
        println!("cargo:rustc-env={name}={value}");
    }
}

/// Keeps every adapter's compiled default synchronized with the repository
/// manifest.
fn write_default_config_store_id() {
    let crate_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("should receive CARGO_MANIFEST_DIR from Cargo"),
    );
    let manifest_path = crate_dir
        .ancestors()
        .nth(2)
        .expect("should resolve the workspace root from CARGO_MANIFEST_DIR")
        .join("edgezero.toml");
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest = match ManifestLoader::from_path(&manifest_path) {
        Ok(manifest) => manifest,
        Err(error) => {
            println!(
                "cargo::error=should load EdgeZero manifest at {}: {error}",
                manifest_path.display()
            );
            std::process::exit(1);
        }
    };
    let Some(config_store) = manifest.manifest().stores.config.as_ref() else {
        println!(
            "cargo::error=should declare [stores.config] in EdgeZero manifest at {}",
            manifest_path.display()
        );
        std::process::exit(1);
    };
    let default_store_id = config_store.default_id();
    println!("cargo:rustc-env=TRUSTED_SERVER_DEFAULT_CONFIG_STORE_ID={default_store_id}");
}

/// Lists every Rust source file under `src` for the migration guard, so a
/// file added to or removed from core joins or leaves the guard on its own.
fn write_migration_guard_sources() {
    // Cargo walks a directory named here, so adding, renaming or deleting a
    // source file reruns this script and the guard list follows the tree.
    println!("cargo:rerun-if-changed=src");

    let manifest_dir =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("should read CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");

    let mut sources = Vec::new();
    collect_rust_sources(&src_dir, &src_dir, &mut sources);
    sources.sort();

    let mut generated = String::from(
        "// Generated by build.rs. Every Rust source file under `src`, so a file\n\
         // added to or removed from core joins or leaves the guard on its own.\n\
         const CHECKED_SOURCES: &[(&str, &str)] = &[\n",
    );
    for relative in &sources {
        let absolute = format!("{}/{relative}", path_literal(&src_dir));
        generated.push_str(&format!(
            "    (\"{relative}\", include_str!(\"{absolute}\")),\n"
        ));
    }
    generated.push_str("];\n");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("should read OUT_DIR"));
    fs::write(out_dir.join("migration_guard_sources.rs"), generated)
        .expect("should write the migration guard source list");
}

/// Collects every `.rs` file under `dir`, as a path relative to `root` with
/// forward slashes, so the generated file reads the same on every platform.
fn collect_rust_sources(root: &Path, dir: &Path, sources: &mut Vec<String>) {
    let entries = fs::read_dir(dir).expect("should read a source directory");
    for entry in entries {
        let entry = entry.expect("should read a source directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect_rust_sources(root, &path, sources);
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .expect("should strip the source root prefix");
            let relative = path_literal(relative);
            if relative != EXCLUDED {
                sources.push(relative);
            }
        }
    }
}

/// Renders a path for a Rust string literal, with forward slashes so a Windows
/// path needs no escaping.
fn path_literal(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}
