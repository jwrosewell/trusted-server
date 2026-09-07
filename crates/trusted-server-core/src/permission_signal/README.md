# Permission signals

A permission is the primitive. This is the seam that decides whether one is
set, and it is open so that a new way of learning a permission can be added
without changing core.

"Signal" rather than "consent" because consent is only one of the things
arriving here. Global Privacy Control is a setting a browser sends, not an
answer anyone gave to a question, and a jurisdiction rule is neither. Consent
is one kind of signal, so the seam takes the wider name and the consent
subsystem keeps the narrower one.

## The hierarchy

Permissions are resolved in layers, each amending the one before.

```text
  country / region rules      the baseline: granted, requires-signal, denied
        |
        v
  source 1  (configured order)     may amend
        |
        v
  source 2                          may amend
        |
        v
  ...                               may amend
        |
        v
  the permission state for this request
```

The baseline comes from `permissions.yaml`, keyed by country and region, with
a default for a request whose place is unknown. A geo provider supplies the
place. No geo provider means no country, and the baseline falls to its floor.

Sources are then asked in order. Each sees what the sources before it settled
on and may amend it. A source with no opinion returns `Neutral` and leaves the
prior value standing, which is different from refusing.

## The order is the policy

The last source with an opinion decides, so the order is the policy. It is a
deployment's to set, not this code's to assume.

```toml
[permission_signal]
sources = ["gpc", "gpp-sale-opt-out", "us-privacy", "malformed-record", "tcf"]
```

A source not on the list does not run, and there is no separate switch. A
publisher who does not want to act on Global Privacy Control removes `"gpc"`
from the list. Leaving the section out entirely runs every model the build
knows about, in the default order, so a signal is never quietly ignored
because someone forgot to list it. An unknown or repeated name is refused at
startup, so a typo cannot silently stop a model being honored.

The default order asks the signals needing no interaction first and the ones
following a prompt after. Global Privacy Control withdraws personalisation on
arrival, and a visitor who then answers a prompt has their answer applied over
it. A deployment wanting the opposite puts the opt-out source last.

Trusted Server takes no view on which model should win. That is a question
about a jurisdiction and a publisher.

## A source can see the others

Amending well sometimes needs to know who set the prior value. A source is
given the whole ordered list and its own position in it, so it can look up a
peer by name, see whether a peer it cares about is configured at all, and ask
a peer directly what that peer makes of a permission.

That is what makes a rule like "personalisation is off, but only because
Global Privacy Control set it, so my answer supersedes it" expressible. The
rule itself belongs to whichever source wants it. This seam only makes the
information available.

Consulting a peer goes one level deep. A source answering a consultation
cannot consult in turn, so two sources asking each other cannot loop.

## Writing a source

Answer `Neutral` for a permission the source has no opinion on, including when
the signal it reads is absent from the request. Returning `Revoke` for an
absent signal turns silence into refusal and would revoke the permission on
every request not carrying that model, which is most of them.

Read the policy for what a signal means rather than inventing a meaning. The
mapping from a permission to a TCF purpose, and which signals count as an
opt-out, are the policy's decisions so that a deployment can change them
without changing a source.

## The models supplied

Core supplies the models it already understood: a US-style opt-out (Global
Privacy Control, a GPP sale opt-out, or a US Privacy string), a consent record
that arrived unreadable, and TCF v2. A deployment configuring nothing gets
those, in that order.
