# The machine identifier

Every stage-1 event carries a `machine_id`. This document says what it is for, what it must not
allow, how it is built, and — importantly — what it does *not* protect against.

## What it is for

The server needs to distinguish these two situations, which look identical without a per-machine
identifier:

- one machine crashing a thousand times (a broken install, low priority for a maintainer);
- a thousand machines crashing once (a released regression, drop everything).

That is the whole requirement. Three concrete uses follow from it:

1. **Distinct-host counts per signature** — the number that decides triage priority.
2. **Per-machine rate limiting** at the server, so one looping host cannot flood the database.
3. **Detecting a machine-specific cause**, e.g. every report for a signature coming from one host
   with a modified package file.

Nothing needs the identifier to be meaningful, resolvable, or permanent. It only needs to be
*equal to itself* and *different from other machines'*.

## Threat model

"Cannot be traced back" is not one property. The identifier must resist three distinct attacks,
assuming an adversary who has obtained the crash database:

| # | Attack | Requirement |
| --- | --- | --- |
| T1 | **Recovery** — derive the host's real identity from the stored value. | The value must not be, or contain, any identifier used elsewhere. |
| T2 | **Confirmation** — given access to a *suspected* machine, check whether it appears in the database. | The value must not be recomputable by someone standing at the machine. |
| T3 | **Cross-database linkage** — join the crash database against another dataset keyed by the same identifier. | The value must not be derivable from any identifier another system also stores. |

T2 is the one that is easy to get wrong, and it is the reason the obvious design is not enough.

## Why the obvious designs fail

**Raw `/etc/machine-id`.** Fails all three. It is a stable host identifier that systemd, D-Bus
(`/var/lib/dbus/machine-id` is a symlink to it) and any number of other subsystems already use, so
it is a ready-made join key.

**`sha256(/etc/machine-id)`, unsalted.** Resists T1 — the value is 128 bits of randomness, so
inverting the digest is infeasible. But it fails **T2 and T3 completely**, because the file is
world-readable:

```
-r--r--r-- 1 root root 33 /etc/machine-id
```

Any process on the machine — any user, no privileges — can read it and compute the same digest.
An adversary with the database and momentary access to a machine can confirm, with certainty,
whether that machine reported crashes and which ones. Preimage resistance is irrelevant here: the
attacker is never inverting the hash, they are recomputing it. The same reasoning applies to any
scheme keyed on hardware serials, MAC addresses or hostnames.

**Hash of a hardware fingerprint** (CPU model, disk serial, DMI UUID). Same failure as above, plus
it survives an OS reinstall, which makes it *more* identifying than the thing it replaced.

## The implemented scheme

```
salt        = 128 random bits from /dev/urandom, generated on first run
machine_id  = sha256("blankres-machine-v1\0" || salt || "\0" || trim(/etc/machine-id))
```

- The salt is generated once, stored in the daemon's state file
  (`/var/lib/blankres/state.json`, root-owned), and **never transmitted**.
- The domain separator prevents the digest colliding with any other hash of the same input.
- `/etc/machine-id` is trimmed, so a trailing newline does not change the identity.

This defeats T2: the value cannot be recomputed from the machine without also reading a root-owned
secret. It defeats T3 for the same reason — no other system knows the salt, so no other dataset
can hold a matching key. T1 was never the binding constraint but is satisfied too.

### An honest note on what the salt actually does

With a locally generated random salt, the `/etc/machine-id` input contributes nothing to the
security of the scheme. `sha256(salt || machine_id)` and `sha256(salt)` are equally unlinkable;
the identifier is, in substance, **a random per-installation token that happens to be derived
through a hash**. The machine-id is there for readability of intent rather than strength.

The practical consequences are worth stating plainly, because they are properties of a random
token, not of the machine-id:

- Losing or resetting the state file produces a **new identity**. Reinstalling the OS does too.
- Copying a disk image to many machines clones the salt, so every clone reports as **one machine**
  until the state files diverge. If cloning is expected in your fleet, the daemon should drop the
  salt when it detects that `/etc/machine-id` has changed since the salt was written.

If you would rather the identifier survive a state-file loss, the only honest way to get that is
to derive it from something durable — which reintroduces T2. That trade cannot be avoided, only
chosen.

## Residual risks

The identifier is not the only thing in a report that identifies a machine, and treating it as the
whole of the privacy story would be a mistake.

- **Rejoining by content.** Distro, version, kernel release, architecture and the set of packages
  a host crashes in form a fingerprint. On a small fleet this can be more identifying than the id.
- **Indefinite linkage.** The identifier never rotates, so the server can link a machine's reports
  across years. Nothing in the stated requirements needs more than a few weeks.
- **Network-level identity.** The server sees the source IP of every stage-1 event. No client-side
  identifier scheme addresses that.
- **Stage-2 payloads.** A core dump is a copy of process memory and can contain anything. That is
  precisely why it requires explicit, per-report consent rather than the one-time stage-1 opt-in.

## Hardening options, if the requirements change

**Rotating pseudonym.** Bucket the identifier by time so linkage is bounded:

```
epoch       = floor(days_since_epoch / 30)
machine_id  = sha256("blankres-machine-v2\0" || salt || "\0" || epoch)
```

The server still counts distinct hosts correctly within a window, and can no longer follow one
machine across windows. The cost is that "this host has been crashing since March" is no longer
answerable, and per-machine rate limits reset at each boundary.

**Server-side pepper.** Have the server HMAC the received identifier under a key held only by the
server before storing it. A database leak then yields values that cannot be checked against any
machine even by an attacker who obtains a client's salt.

**Drop it entirely.** If only "how many distinct machines" matters, a probabilistic sketch
(HyperLogLog over the identifier, discarding the value) answers that question without storing a
per-machine value at all. This is the strongest option and costs the two diagnostic uses above.
