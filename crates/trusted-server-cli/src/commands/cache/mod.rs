//! `ts cache` — operator control over shared template and origin caches.

pub(crate) mod purge;

use clap::Subcommand;

use crate::error::CliResult;
use crate::fastly_cli::FastlyProcess;

/// Subcommands under `ts cache`.
#[derive(Debug, Subcommand)]
pub(crate) enum CacheCommand {
    /// Purge cached templates and tagged origin responses through the hosting platform's purge API.
    Purge(PurgeArgs),
}

/// Arguments for `ts cache purge`.
///
/// # Why this asks the platform rather than the service
///
/// A purge is administration, and the service answers readers on the publisher's own
/// domain. Asking the platform leaves the credential that can empty the cache with the
/// platform's access control, which ties a token to the user who made it, can limit it
/// to purging by key and can revoke it, and keeps that credential off the domain every
/// reader reaches.
///
/// The surrogate key is derived here by the function the service tags its cached objects
/// with, so the command cannot drift out of agreement with the cache it is purging.
#[derive(Debug, clap::Args)]
pub(crate) struct PurgeArgs {
    /// The Fastly service whose cache is purged.
    #[arg(long, value_name = "ID")]
    pub(crate) service_id: String,

    /// Purge every cached template and tagged origin response.
    #[arg(long, conflicts_with = "page")]
    pub(crate) all: bool,

    /// Purge one reader-facing page URL, including its exact scheme, host, and port.
    #[arg(long, conflicts_with = "all")]
    pub(crate) page: Option<String>,
}

/// Run a `ts cache` subcommand with the token from [`crate::fastly_cli::TOKEN_VARIABLE`].
///
/// # Errors
///
/// Returns an error when neither scope is given, when the token is absent from the
/// environment, or when the platform refuses the purge.
pub(crate) fn run(command: &CacheCommand, out: &mut impl std::io::Write) -> CliResult<()> {
    match command {
        CacheCommand::Purge(args) => {
            // Checked before the token is asked for, so a mistyped command is corrected
            // without one.
            purge::purge_target(args)?;
            purge::run_purge(args, &FastlyProcess::from_environment()?, out)
        }
    }
}
