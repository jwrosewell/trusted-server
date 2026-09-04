# Cache providers

Asset cache provider crates live here, one per implementation, each
implementing the `PlatformAssetCache` trait from `trusted-server-core`:

- `crates/cache/51degrees` (`trusted-server-cache-51degrees`) is a
  memory-bound cache for a deployment with nothing in front of it. It stores
  raw origin responses in the process, bounded by bytes rather than by number
  of entries, and expires each entry on a lifetime derived from the origin's
  own `Cache-Control`. It is plain Rust with no host SDK, so any native
  adapter can inject it. The Axum adapter does, via `build_asset_cache`.
- Further providers (for example `crates/cache/<vendor>`) slot in alongside
  it, one per implementation, selected by the `[cache] provider` setting.

The host-neutral `PlatformAssetCache` trait and the `UnavailableAssetCache`
default (stores nothing, reports "unsupported") both live in
`trusted-server-core`, so a deployment with no provider selected caches no
assets and behaves exactly as it did before this directory existed.

## Which cache this is

Three caches are easy to confuse and they are not the same thing.

| Cache            | Holds                                 | Lives in                                            |
| ---------------- | ------------------------------------- | --------------------------------------------------- |
| The host's own   | Whatever the platform decides         | Fastly, Cloudflare and the like. Not code here.      |
| Template cache   | Assembled page templates              | `trusted-server-core/src/platform/template_cache.rs` |
| **Asset cache**  | **Raw origin responses for assets**   | **This directory, plus the trait in core.**          |

The template cache stores a page after `lol_html` has transformed it, keyed
and invalidated around advertisement slots. This one stores stylesheets,
scripts, fonts and images exactly as the origin sent them. Different key,
different lifetime, different invalidation, so it has its own trait rather
than borrowing that one.

## Why a provider needs to exist at all

At the edge the platform already caches, and the adapter is a thin wrapper
over it. A deployment with nothing in front of it has no such platform, so
every request for every asset reaches the publisher's origin every time. On
one measured publisher page, nineteen stylesheets alone were fetched.

## The rule a shared cache must not break

The template cache already fought this and its rules are worth reading before
changing anything here: `REPLAYABLE_POLICY_HEADERS`, `VarySpec` and the
eligibility gate in `trusted-server-core/src/platform/template_cache.rs`. A
shared cache that stores one reader's response and serves it to the next is a
data breach, not a bug.

Assets are usually reader-neutral, but not always. A signed URL, a per-reader
token in a query string, or an origin that varies an asset by cookie all
break the assumption. The rules this cache holds to are written down and
enforced in `AssetCacheEligibility` in
`trusted-server-core/src/platform/asset_cache.rs`, so a provider crate here
never has to decide for itself what is safe to store: it is handed a key and
an entry that already passed the gate.

## Adding a provider

1. Create `crates/cache/<vendor>` with its own `name` and `description` and
   everything else inherited from the workspace, plus `[lib] doctest = false`
   and `[lints] workspace = true`.
2. Add the path to the workspace `members` list in the root `Cargo.toml`.
3. Implement `PlatformAssetCache`, returning a stable `id()`.
4. Add the provider key to `CacheSettings::validate_provider_selection` in
   `trusted-server-core/src/settings.rs`, so an unknown key is rejected at
   startup rather than silently disabling the cache.
5. Inject it from the adapter through `build_asset_cache`. Core never names a
   vendor.
