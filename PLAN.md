# Plan: Selectable security levels (L1/L2), Level 3 deferred

**Status:** Built and reviewed to target. Implementation went through 2
rounds of adversarial code review: round 1 found 2 major issues (9.3/10,
both fixed and test-covered), round 2 confirmed both genuinely fixed with
no regressions (**9.7/10**, matching the base v2 system's own bar). 160
tests passing. Plan itself separately converged to 9.5/10 across 6
adversarial design-review rounds before build.

## Implementation review log
- **Round 1 code review: 9.3/10.** All eight of the plan's pinned-down
  mechanisms (once-per-cycle level read, dict-based dedup, allow-list
  exemption's AND-with-negation in both places it appears, atomic
  transition-only alert, `get_pending` mid-flow exception, hardcoded-safe
  fallback) were verified correctly implemented and well-tested. Two real
  gaps found: (1) the plan's own two sections disagreed with each other --
  "Where the level lives" said `default_security_level` seeds the state
  store on first run, but build step 1's literal wording ("hardcoded-safe
  default 2... independent of config") led the implementation to make the
  now-required config key dead, doing nothing; (2) `security_level_since`
  was updated on every `set_level()` call including idempotent re-sets
  (e.g. a redundant click on an already-selected popup segment), which
  would silently reset the staleness clock the heartbeat's L1-too-long
  check depends on.
- **Fixed**: `SecurityLevelStore` now takes a `default_level` constructor
  param, threaded from `config.access["default_security_level"]` in both
  `main.py` and `popup_app.py`, and used as `get_level()`'s fallback
  instead of the bare module constant -- reconciling the plan's two
  sections (config genuinely seeds the first-run value; the hardcoded
  literal `2` is a fallback-of-the-fallback, used only if no default_level
  is supplied at all, so a missing/invalid config value still can never
  silently resolve to the more permissive level). `set_level()`'s mutate
  closure now only writes `security_level_since` when `old_level !=
  new_level`, so an idempotent re-set of the already-active level leaves
  the staleness clock untouched.

## What this is
Adds a runtime-selectable "security level" to the existing challenge/response
system (PLAN.md v2, currently built and reviewed to 9.7/10, unchanged
otherwise): Level 1 drops the sender allow-list check (any authenticated
sender can attempt the phrase), Level 2 is today's system unchanged. A third
level (passphrase + allow-list + a physical USB/FIDO2 hardware key) was
discussed and is **explicitly deferred**, not built now -- see "Deferred:
Level 3" below for why.

## Design

### Level definitions
- **Level 1**: sender must still pass DKIM/SPF/DMARC authentication (nothing
  about that check changes -- this is not "accept spoofed mail"), but the
  `allowed_senders` allow-list check is skipped. Any authenticated sender's
  trigger is processed exactly like an allow-listed one is today (challenge
  issued, keyed by their address; suffix reply checked the same way; their
  own lockout counter applies).
- **Level 2**: unchanged from today -- sender must be authenticated AND on
  `allowed_senders`.

### Real security delta between L1 and L2, stated plainly (grounded in the
actual code, verified by adversarial review against the real `notifier.py`,
not assumed)
`notifier.py`'s every outbound email (`send_challenge_prefix`,
`send_session_link`, all alerts) sends to the single fixed
`config.notify.alert_to` address -- never back to whoever the trigger's
sender was (confirmed: `Notifier.__init__` binds `self.alert_to` once, and
every send path routes through it). This means a stranger triggering at
Level 1 from an unrecognized address **never sees the disclosed prefix
reply** and so cannot complete the suffix-reply step without already
knowing the full phrase through some other leak.

**Corrected framing (round-1 adversarial review caught this being
undersold): Level 1 is not "L2 plus minor nuisance" -- it is a categorically
weaker authentication scheme, secret-only instead of identity+secret,
whenever the phrase leaks by any channel other than compromising the
alert_to inbox itself.** At L2, someone who somehow learns the full
passphrase (shoulder-surfed off the popup screen, read off
`secrets/phrase.txt` via some other access to the machine, leaked through
an entirely separate channel) still cannot complete a login without ALSO
being DKIM/SPF/DMARC-authenticated as one of the specific
`allowed_senders` addresses. At L1, that second factor is simply gone. This
is the real, named tradeoff of choosing L1 -- not a minor variant, a
different (weaker) authentication model, chosen deliberately for
convenience. Two additional distinct concrete exposures, on top of that
core tradeoff:
- **Volumetric/flood surface the per-sender defenses don't cover**
  (see "Aggregate flood cap" below) -- an attacker who doesn't even know
  the phrase can still cause real load and noise using many disposable
  sender addresses, since `LockoutTracker` and the abandoned-challenge
  counter are both keyed per-sender and don't aggregate.
- **No standing signal that L1 is active** (see "Notification and staleness
  signal" below) -- addressed in this revision.

### Where the level lives
A new `security_level` field (`1` or `2`) in the shared `StateStore` (not
`config.yaml`) -- consistent with how the pending-challenge/rotation-cooldown
state already lives there, and so a level change from the popup takes effect
on `mail_watcher`'s very next poll cycle without restarting the service.
`config.yaml` gets one new key, `access.default_security_level`, used only
to seed the state store's value the first time.

**Safe-default fix (addresses round-1 finding M2)**: the in-code fallback if
`default_security_level` is absent from a user's already-deployed
`config.yaml` (gitignored, not auto-regenerated) MUST be the hardcoded
literal `2`, never read as `config.access.get("default_security_level", 1)`
-- a missing key must never silently seed the MORE permissive level.
Additionally, `default_security_level` is added to `config.py`'s
`_REQUIRED_SCHEMA["access"]` list so a config missing it fails loudly at
boot (matching this project's own stated "fail helpfully, not silently"
philosophy) rather than falling through to any fallback at all.

New tiny module `security_level_store.py` (same pattern as
`challenge_store.py`'s thin wrapper over `StateStore`): `get_level()`,
`set_level(level, notifier=None)` (see notification behavior below), plus
`record_new_sender_if_l1(sender)` / `l1_new_sender_cap_exceeded()` for the
rolling flood cap (see below) -- kept separate from `ChallengeStore` since
this is a different concern (a standing config knob + its own narrow
flood-defense counter, not challenge lifecycle state), consistent with
this codebase's existing one-responsibility-per-module style.

**Call-site placement, pinned down (addresses round-2 finding N1)**:
`mail_watcher.py`'s `poll_once()` calls
`security_level_store.record_new_sender_if_l1(sender)` itself, in the main
per-message loop, BEFORE calling `_handle_allowed_sender` -- not inside
`_handle_allowed_sender`. This keeps `_handle_allowed_sender`'s existing
responsibility (deciding whether THIS message is handled) separate from
the cycle-level bookkeeping of how many distinct new senders have been seen
recently, mirroring how `poll_once()` already owns `to_archive` batching
and the `sweep_expired()` call itself, rather than pushing cycle-level
concerns down into the per-message handler.

### mail_watcher.py change
In `poll_once`, the existing gate:
```python
if sender not in self.allowed_senders:
    ...archive...
```
becomes conditional on the current security level. **Round-1 adversarial
review caught a real race here**: if `security_level_store.get_level()`
were called inline at the per-message gate (inside the `for msg_id in
msg_ids` loop), a level change mid-cycle could let some messages in the
SAME batch be gated by the old level and others by the new one -- a
non-atomic policy split within one poll cycle, directly contradicting this
codebase's whole atomicity story (`challenge_store.py`'s docstring is
explicit that its design assumes one poll cycle is one atomic unit of
policy). **Fixed**: `poll_once()` reads `security_level_store.get_level()`
exactly ONCE, at the very top (alongside the existing `sweep_expired()`
call), into a local variable passed down through `_handle_allowed_sender`
-- never re-read per-message. A level change takes effect on the NEXT full
cycle, never mid-cycle. The authentication check itself
(`check_authenticated`) is **never** skipped at either level.

### Aggregate flood cap (new, addresses round-1 finding M1; tightened round 3)
`LockoutTracker` and the abandoned-challenge counter are both keyed per
sender address -- fine at L2 (the attacker can't cheaply mint allow-listed
identities) but NOT fine at L1, where an attacker controls how many
"senders" exist simply by using disposable addresses, each getting its own
independent 5-attempt lockout budget and 10/hour abandoned-challenge
budget that never aggregate. The existing `flood.threshold_per_cycle`
(default 100) only logs a warning today -- it does not stop processing, so
a burst of many distinct never-before-seen senders in one L1 cycle would
still each get a challenge issued, a synchronous `send_challenge_prefix`
call (up to 5 retries x 10s backoff), and an email to the owner, before
being archived.

**Round-2 attempt used a per-cycle counter (reset every ~15s poll) --
round-2 adversarial review correctly caught that this defends only against
a BURST, not a sustained attacker: pacing at 9 new disposable senders every
cycle indefinitely produces the identical total hourly volume/noise, just
spread out instead of bursty, completely untouched by a per-cycle reset.**

**Fixed in round 3 -- use a ROLLING window, matching this codebase's own
already-correct pattern** (the existing abandoned-challenge threshold is
explicitly a rolling 1-hour window, not a per-cycle one, for exactly this
reason). **Round-3 adversarial review then caught that the FIRST attempt at
this got the data structure wrong**: "a timestamp list, same shape as
`abandoned_events`" has no sender identity in it at all -- you cannot
determine "is this the first time THIS sender was seen in the window" from
a bare list of numbers. That instruction was literally unbuildable as
stated.

**Fixed for real in round 4 -- the actual data structure, spelled out**:
`new_sender_last_seen` is a **dict** mapping `sender -> last_seen_timestamp`
(not a plain timestamp list) -- one entry per distinct sender, not one
entry per trigger. `record_new_sender_if_l1(sender)`: if `sender` is
already a key, just update its timestamp (does NOT count as a new
occurrence -- this is what actually preserves the distinct-senders-not-
raw-triggers property round 3 was asked to verify and got wrong); if it's
a new key, insert it. Before either step, prune any entry whose timestamp
is older than 1 hour. `l1_new_sender_cap_exceeded()` returns whether
`len(new_sender_last_seen)` (after pruning) exceeds the threshold -- i.e.
the count of DISTINCT senders with at least one trigger in the trailing
hour, which is exactly what this cap is supposed to measure, correctly
separated from raw trigger-volume (already handled by per-sender lockout)
and from abandoned-challenge volume (already handled by
`ChallengeStore.sweep_expired`).

**Allow-listed-sender exemption, decided explicitly (round-3 review found
this was a completely undiscussed self-DoS gap)** -- note this is a SECOND,
unrelated use of the allow-list, easy to misread as contradicting Level 1's
whole premise: Level 1 never consults `access.allowed_senders` to decide
whether to GRANT access (that's the entire point of Level 1). This is the
one and only other place the allow-list is consulted at Level 1, for a
completely different purpose -- protecting the owner's own address from
being counted against a flood defense that exists solely to bound OTHER
(unknown) senders' behavior. `record_new_sender_if_l1`
and the cap check are skipped entirely for any sender already in
`access.allowed_senders` -- the cap exists specifically to bound L1's
lack of an identity check for UNKNOWN senders; the owner's own known-good
address must never be capable of being silently archived by this specific
defense, at either security level. This is a cheap check (the allow-list is
already loaded) and closes a real "the flood cap could DoS the legitimate
owner during an actual attack" gap that round 3 correctly flagged as
unaddressed.

**Threshold value, re-derived with matching units (round-3 review correctly
called out the original comparing a DAY-scale estimate to an HOUR-scale
limit and called it a mismatch, not real derivation)**: `access.
l1_max_new_senders_per_hour`, default **15**. Reasoning, units matched this
time: expected worst-case legitimate distinct-new-sender volume at L1 is
up to 5 **per day** (per the existing style of estimate used for the
abandoned-challenge threshold) -- sizing the hourly cap at 15 means even
if that ENTIRE day's worst-case legitimate volume happened to land
concentrated within a single hour (the same "all of a bad day's expected
volume compressed into one hour" reasoning the existing 10/hour abandoned
threshold explicitly uses), there is still 3x headroom above that
single-hour concentration -- comparing single-hour-to-single-hour, not
day-to-hour.

Once `l1_new_sender_cap_exceeded()` is true, remaining NEW (non-allow-
listed, not-already-tracked) senders' triggers are archived without
challenge issuance for the rest of that rolling window (same "rejected,
not a strike" treatment as an already-occupied slot); the event is logged
and feeds the same degraded-heartbeat reporting path as the existing
abandoned-flood threshold (a new distinct state string, not conflated with
it). This lives in `security_level_store.py` (not `challenge_store.py`)
since it's specifically about L1's identity-cap absence, not challenge
lifecycle.

### Notification and staleness signal (new, addresses round-1 findings M3/M4;
mechanism fully specified in round 3 -- round 2 stated the desired outcome
but not how it's actually detected/stored, which adversarial review
correctly flagged as the same category of gap C1 was raised over)

**Stored schema, spelled out explicitly this time**: `StateStore` gains TWO
fields under this feature, not one -- `security_level` (unchanged from
before) AND a new `security_level_since` (a timestamp, seconds since
epoch, updated every time the level actually changes). Both are read/written
together, atomically, in the same `StateStore.update()` call.

**Transition-detection mechanism, spelled out explicitly**:
`security_level_store.set_level(new_level, notifier=None)` does, as a
single atomic `StateStore.update()`:
1. Read the CURRENTLY stored level (`old_level`) from the same data dict
   being mutated (not a separate prior `read()` call -- avoids a
   read-then-write race, consistent with every other atomic pattern already
   used in `challenge_store.py`).
2. Write `security_level = new_level` and `security_level_since =
   time.time()`.
3. Only if `old_level != 1 and new_level == 1` (a genuine transition INTO
   Level 1, not e.g. an idempotent re-set of an already-active Level 1, and
   not a transition OUT of it), and only if `notifier` was passed, call
   `notifier.send_security_level_alert()` -- this is what "not on every
   call" concretely means: an explicit `old_level`-vs-`new_level` comparison
   inside the same atomic operation that performs the write, not an
   `if level == 1` check that would fire on every call.

**Heartbeat check, now buildable against the real schema**: `heartbeat.py`'s
new fourth check reads `security_level` and `security_level_since` from the
state store; if `security_level == 1` and `time.time() - security_level_since
> access.l1_max_continuous_hours * 3600` (new config key, default 24),
report a distinct degraded state ("Level 1 has been active for over 24h")
-- detection-only, consistent with the phrase-rotation-overdue check's own
explicitly-accepted "visibility, not remediation" scope. This directly
addresses the realistic failure mode of flipping to L1 for one temporary
need and forgetting to flip back.

### Popup UI change
`popup_app.py` gets a new segmented control, "SECURITY LEVEL" (LEVEL 1 /
LEVEL 2), styled identically to the existing STYLE toggle, writing
immediately to `security_level_store` on change -- physical-access-only by
the same trust boundary as every other popup control.

## Decisions made
- **Level 1 still requires passing DKIM/SPF/DMARC authentication** -- only
  the allow-list identity check is dropped, not sender authenticity.
  Confirmed with the user as the intended scope (not "accept anything").
- **The level is chosen via the popup, not `config.yaml` or the trigger
  phrase itself** -- per-request level selection (e.g. via a special
  trigger keyword) was considered and rejected: it would need to be
  decidable from an unauthenticated message alone, which conflicts with
  wanting Level 1/2 to be a deliberate, physical-access-only owner choice
  rather than something a remote sender can invoke on demand.
- **Level 3 (USB/FIDO2 key) is deferred, not built now** -- see below.

## Deferred: Level 3 (physical key)
Level 3 (passphrase + allow-list + a physical key inserted **on the
accessing device**, not the target laptop) was designed down to a concrete
technical decision. **Round-1 adversarial review flagged that the original
deferral reasoning was incomplete** -- noted here for whenever this is
revisited, not built now (user's explicit choice): the fixed-origin
requirement only applies to the origin hosting the WebAuthn
registration/verification ceremony itself, not to whatever serves the
actual VNC session afterward. A small, separate, fixed-hostname service
(e.g. a free Cloudflare Pages/Workers subdomain) could host ONLY the
WebAuthn ceremony -- register the credential there once, perform the
ceremony there after the suffix-match succeeds, then hand off to that
session's normal freshly-minted random tunnel URL for the actual VNC
connection. This would let Level 1/2 keep the random-per-session-hostname
property entirely, at the cost of a much smaller commitment (one small
fixed-domain static service) than "give up random tunnel hostnames
altogether." Offered to the user; declined for now (still don't want to
deal with a domain at all yet) -- but this is the design to pick back up
with, not the original "switch everything to a named tunnel" framing.
- A plain USB flash drive can't be checked from a browser page at all --
  browsers don't expose raw USB mass-storage devices to JavaScript. The
  only real way to do this is **WebAuthn/FIDO2** (the standard hardware
  security key browser API), self-hosted (our own registration/verification
  code, no third-party auth service), with a real FIDO2 USB key (e.g. a
  YubiKey) -- not a generic flash drive.
- WebAuthn credentials are bound to a **fixed origin (domain)**. This
  system's tunnel currently mints a fresh random Cloudflare hostname
  (`*.trycloudflare.com`) every session by design (single-use, unguessable,
  nothing standing) -- a key registered under one random hostname will not
  validate under the next session's different hostname. Level 3 therefore
  requires switching (at least for Level 3 specifically) to a **stable
  named Cloudflare tunnel** on a domain the user owns.
- The user does not currently have/want to commit a domain for this, so
  Level 3 is deferred rather than built against a design that can't work
  yet. **Revisit when a fixed domain is available** -- at that point this
  becomes: register a FIDO2 credential once (via a setup flow at the fixed
  domain), then Level 3's portal step, after the existing suffix-match
  succeeds, prompts a WebAuthn ceremony before granting the session.

## Decisions made (round 4, post-third-adversarial-review)
- **Security level is read exactly once per poll cycle**, not per-message
  -- closes the mid-cycle race a literal reading of the original build
  steps would have introduced.
- **L1's real tradeoff is stated as "secret-only vs. identity+secret"**,
  not soft-pedaled as mere nuisance -- the honest framing the round-1
  review demanded.
- **The new-sender flood cap uses a ROLLING 1-hour window over a dict
  keyed by sender identity** (`new_sender_last_seen: sender ->
  last_seen_timestamp`, default cap 15/hour), not a per-cycle counter and
  not a bare timestamp list -- two separate fixes across two rounds: round
  2's per-cycle version defended only against bursts, not sustained
  pacing; round 3's first rolling-window attempt named a data structure
  (a plain timestamp list) that couldn't actually distinguish "one sender
  many times" from "many distinct senders," which would have silently
  collapsed this cap into the already-separately-handled per-sender-lockout
  problem. The dict-by-sender structure is what actually makes "count of
  DISTINCT senders in the window" buildable.
- **Allow-listed senders are exempt from the flood cap entirely** -- round
  3 found this completely undiscussed: without the exemption, a sustained
  attack tripping the cap would also silently archive the legitimate
  owner's own triggers, since L1 has no identity check left to exempt
  against otherwise. Decided explicitly now, not left implicit.
- **The 15/hour threshold is justified with matching units** -- comparing
  the cap against the worst-case legitimate volume CONCENTRATED INTO ONE
  HOUR (mirroring the existing abandoned-threshold's own reasoning style),
  not comparing an hourly cap against a daily volume estimate the way the
  first attempt at this number did.
- **The counter lives in `security_level_store.py` and is incremented by
  `poll_once()` itself, before calling `_handle_allowed_sender`** -- not
  inside `_handle_allowed_sender` -- keeping per-message handling and
  cycle-level bookkeeping separate, pinned down explicitly after round 2
  left this ambiguous.
- **Entering Level 1 emails an alert via an explicit `old_level`-vs-
  `new_level` comparison inside the same atomic `StateStore.update()` that
  performs the write** -- not an `if level == 1` check, which round 2 left
  unspecified and could have fired on every call rather than only on
  genuine transitions.
- **A new `security_level_since` timestamp field is added to the stored
  state alongside `security_level`**, updated on every change -- round 2
  referenced heartbeat reading "the last-transition timestamp" without ever
  specifying where that timestamp would live; this closes that schema gap.
- **The safe fallback for a missing `default_security_level` config key is
  hardcoded to `2`**, and the key is added to the required schema so a
  missing value fails loudly at boot instead of silently.
- **Level 3 stays deferred** (user's explicit choice), but with the
  corrected design noted (decoupled fixed-domain WebAuthn RP, not "give up
  random hostnames entirely") so it isn't picked back up on the same flawed
  premise later.

## Open questions
None blocking -- L1/L2 scope is fully resolved across all three review
rounds. Level 3's revival is gated on the user deciding to set up even a
small fixed domain, not on any remaining design ambiguity.

## Build steps
1. Add `security_level_store.py`:
   - `get_level()` -- reads `StateStore`, returns the hardcoded-safe
     default `2` if `security_level` was never set (independent of config).
   - `set_level(new_level, notifier=None)` -- single atomic
     `StateStore.update()`: reads `old_level` from the same dict being
     mutated, writes `security_level = new_level` and
     `security_level_since = time.time()`, and calls
     `notifier.send_security_level_alert()` (new `Notifier` method, plain
     email like its siblings) only when `old_level != 1 and new_level == 1`
     and `notifier` is not None.
   - `record_new_sender_if_l1(sender)` -- no-op unless the current level is
     1 **AND** `sender` is NOT in `access.allowed_senders` (round-5 fix: an
     earlier draft of this condition was written as an OR, which inverts
     the exemption and would have let the owner's own address consume a
     slot in the distinct-sender count at L1 -- the correct condition only
     does work when BOTH "level is 1" and "sender is unknown" hold).
     Otherwise: prune `new_sender_last_seen` (a **dict**, `sender ->
     last_seen_timestamp` -- NOT a timestamp list; this is what makes
     distinct-sender dedup actually possible) of entries older than 1 hour,
     then insert-or-update `sender`'s timestamp.
   - `l1_new_sender_cap_exceeded()` -- returns whether (post-prune)
     `len(new_sender_last_seen)` exceeds `access.l1_max_new_senders_per_hour`.
2. Add `access.default_security_level: 2`, `access.l1_max_new_senders_per_hour: 15`,
   and `access.l1_max_continuous_hours: 24` to `config.example.yaml`; add
   `default_security_level` to `config.py`'s `_REQUIRED_SCHEMA["access"]`
   list (fails loudly at boot if absent).
3. `mail_watcher.py`: at the TOP of `poll_once()` (alongside the existing
   `sweep_expired()` call), read `security_level_store.get_level()` ONCE
   into a local variable for the whole cycle. In the per-message loop,
   BEFORE calling `_handle_allowed_sender`, call
   `security_level_store.record_new_sender_if_l1(sender)` (cheap no-op at
   L2 or for an allow-listed sender, so unconditional placement here is
   fine); if `l1_new_sender_cap_exceeded()` is true AND `sender` is not
   allow-listed AND `self.challenges.get_pending(sender)` (the existing
   `ChallengeStore` lookup, already used elsewhere in this file) returns
   `None`, archive without calling `_handle_allowed_sender` at all (same
   "rejected, not a strike" treatment as an occupied slot) -- this
   exception exists so the cap only ever blocks a sender's FIRST trigger
   once tripped, never cuts off a sender who was already mid-flow before
   the cap tripped and is now legitimately replying to their own
   already-issued challenge. Otherwise, thread the cycle's
   resolved level into `_handle_allowed_sender` so the `sender not in
   self.allowed_senders` gate is skipped only when that level is 1.
   Authentication (`check_authenticated`) is never conditional.
4. `heartbeat.py`: add the Level-1-active-too-long check, reading
   `security_level` and `security_level_since` from `security_level_store`;
   if level is 1 and `time.time() - security_level_since` exceeds
   `access.l1_max_continuous_hours * 3600`, report a distinct degraded
   state.
5. `notifier.py`: add `send_security_level_alert()` (states which level is
   now active), matching the existing plain-email pattern of its siblings.
6. `popup_app.py`: add the SECURITY LEVEL segmented control, wired to
   `security_level_store.set_level()` (passing the popup's own `notifier`
   instance), styled like the existing STYLE toggle. Visually indicate when
   L1 is active near the allow-list display, since the list isn't enforced
   in that state.
7. `main.py`: construct and pass `security_level_store` into `MailWatcher`
   alongside the existing `challenges`/`lockout`/etc. dependencies.
8. Tests (written fresh, no reusable existing pattern to copy -- the style
   toggle has no persistence today): Level 1 accepts a non-allow-listed
   authenticated sender's trigger/reply cycle; Level 2 still rejects one
   (regression guard); security level is read once per cycle, not
   per-message (a level flip mid-batch doesn't split policy within that
   cycle); `security_level_store` get/set/default-seeding-is-hardcoded-safe;
   the alert fires ONLY on a genuine old-level-1/new-level-transition (not
   on every `set_level()` call, not on transitions OUT of level 1);
   `security_level_since` is actually persisted and updated; the rolling
   new-sender cap triggers past the hourly threshold and does NOT apply at
   Level 2; pacing new senders slowly (spread across many cycles, never
   bursting) still trips it once the rolling DISTINCT-sender count crosses
   the threshold; the SAME sender triggering many times does NOT by itself
   count toward the cap (only counted once per hour, regardless of trigger
   count -- proving the dict-by-sender structure actually distinguishes
   "one sender repeatedly" from "many distinct senders"); an allow-listed
   sender is NEVER archived by the cap even during an active flood from
   other senders; heartbeat's L1-too-long detection.
9. Update `README.md` to mention the security-level toggle, its config
   keys, and the deferred Level 3 (with the corrected decoupled-RP design
   noted for later).
