# 51Degrees Integration

**Category**: Location, Device and Identity
**Status**: Production
**Type**: Vendor module supplying three providers

## Overview

The 51Degrees module resolves a request's location, its device and a
51Degrees identifier (51Did) from one call to a 51Degrees cloud service, and
offers each answer to Trusted Server as a provider. A deployment selects any
combination of the three. The module lives in `crates/geo/51degrees`, outside
core, and core stays neutral about it in the way the
[Integration Guide](/guide/integration-guide) describes for every vendor
module.

One crate supplies all three providers because the service answers all three
questions from one request. A crate per capability would hold a client each
and pay for its own call to the same service.

## How It Works

```
┌──────────────────────────────────────────────────────────────┐
│  Request arrives                                             │
│  ↓                                                           │
│  One call to the 51Degrees service, carrying the client      │
│  address, the User-Agent and the client hints the browser    │
│  left in cookies                                             │
│  ↓                                                           │
│  Location ── [geo] provider ── permission jurisdiction       │
│  Device ──── [device] provider ── bid request device object  │
│  51Did ───── [ec] provider ── Edge Cookie identity           │
└──────────────────────────────────────────────────────────────┘
```

- **Location.** The country and, where the service resolves them, the city
  and coordinates reach the permission model and the bid request. A
  successful answer with no usable country is read as no location, so the
  permission policy's declared jurisdiction applies. A transport failure, a
  non-success status or an unreadable body is read as a failed lookup, so
  the consent gates fail closed. The two are kept apart on purpose, because
  an outage that quietly adopted the policy's default would be the worst
  possible fault here.
- **Device.** The device type, make, model, operating system and screen
  size reach the bid request's device object, which is what a bidder prices
  on. The gate signal that decides whether a request looks like a browser
  is answered from the same call.
- **Identity.** The 51Did the service issues becomes the Edge Cookie
  identity. It is transported in the URL-safe base64 alphabet, because the
  Edge Cookie alphabet refuses `+`, `/` and `=`, and converted back
  exactly whenever it is handed to 51Degrees. A value posted by the browser
  or carried in a cookie is verified against the signer's published key
  before it is trusted, because an identifier taken on trust could be
  anyone's.

## Configuration

The module follows the [Configuration Rules](/guide/configuration-rules).
It runs when `[integration] provider` names it, its settings live in
`[integration.fiftyone_degrees]`, a setting it does not know is refused, and
each provider serves a request only where `[geo]`, `[device]` or `[ec]`
selects the module by name.

```toml
[integration]
provider = ["fiftyone_degrees"]

[integration.fiftyone_degrees]
# The full URL of the JSON endpoint. A self-hosted container carries no key
# in the path because it is authorized by license key at start-up. A
# multi-tenant service keys the path instead, for example
# "https://cloud.51degrees.com/api/v4/<resource key>.json".
endpoint = "http://127.0.0.1:8080/api/v4/json"
timeout_ms = 500
identity = true

[geo]
provider = "fiftyone_degrees"

[device]
provider = "fiftyone_degrees"

[ec]
provider = "fiftyone_degrees"
```

### Configuration Options

| Field                   | Type    | Required | Description                                                                                                                                                                                   |
| ----------------------- | ------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `endpoint`              | string  | Yes      | The full URL of the JSON endpoint, including any resource key the deployment requires in the path.                                                                                            |
| `timeout_ms`            | number  | No       | How long to wait for the service (default: `500`, range: `1`-`10000`). The lookup sits in front of the permission decision, so the default is short.                                          |
| `identity`              | boolean | No       | Whether to ask the service for a 51Did as well (default: `false`). Asking for an identifier is a separate decision from asking where a request came from, and adds no extra round trip.       |
| `critical_client_hints` | boolean | No       | Whether to send `Critical-CH` so the browser retries the first navigation carrying its client hints (default: `true`). Without it the first page view of a session is priced on a User-Agent. |
| `verify_signatures`     | boolean | No       | Whether to verify the signature on a 51Did before accepting it (default: `true`). Off leaves only a shape check, so turn it off with a reason rather than as a default.                       |

### Restrict the key to your domains

A resource key is created in the 51Degrees configurator, which lets you name
the domains it may be used from. A key created without that list works from
anywhere, so anyone who reads it can spend your allowance against your
account. Name your domains for any key used in production. A server-to-server
call sends no origin of its own, so the caller presents one for a restricted
key to work, which the 51Degrees cloud request engine does through its
configured cloud request origin.

## The browser module

When `[device]` or `[ec]` selects the module, the served markup delegates the
high entropy client hints to the configured endpoint with a `Delegate-CH`
meta tag, and the response carries `Accept-CH` and, when
`critical_client_hints` is on, `Critical-CH`. The delegation names the
endpoint a deployment actually wrote rather than the public cloud, so a
publisher group running its own private cloud does not delegate to someone
else's. Only the high entropy hints are delegated, because the low entropy
ones reach third parties already.

The module's own script makes no network call. It gathers what a server
cannot see, the screen size and the high entropy client hints, and leaves
them in the cookies the service's own JavaScript would write, so the server
reads the evidence on the next request whichever script wrote it.

## What the module does not do

- It does not create a 51Did. The service issues one, and the module carries
  it.
- It does not populate the region. The service returns a region name where
  Trusted Server's location type carries an ISO 3166-2 subdivision code, and
  a name written into that field would mis-key every region rule, so the
  field stays unset and the module says so once per process.
- It does not run without being named. Linking the crate into an adapter
  offers the module to a deployment, and nothing runs until
  `[integration] provider` names it.

## Find out more

- [51Degrees IP Intelligence](https://51degrees.com/ip-intelligence?utm_source=github&utm_medium=docs&utm_campaign=trusted-server&utm_content=51degrees-integration&utm_term=ip-intelligence)
- [51Degrees Device Detection](https://51degrees.com/device-detection?utm_source=github&utm_medium=docs&utm_campaign=trusted-server&utm_content=51degrees-integration&utm_term=device-detection)
- [51Degrees identifiers documentation](https://51degrees.com/documentation/_identifiers__index.html?utm_source=github&utm_medium=docs&utm_campaign=trusted-server&utm_content=51degrees-integration&utm_term=51did)
- https://github.com/51Degrees/rust
