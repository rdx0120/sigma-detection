# Wazuh Deployment Notes — Lessons from Real Deployment

This file documents what changed, and what broke, when the two endpoint
rules in this pack (`suspicious_encoded_powershell`, `edr_agent_tampering`)
were deployed as real Wazuh local rules against live Sysmon telemetry in
a reference environment, rather than just validated against the synthetic
fixtures in `tests/`. It's included deliberately — the synthetic-fixture
tests prove the *rule logic* is internally consistent; they do not prove
a rule fires against a real Wazuh ruleset, which turned out to matter.

## Lesson 1: `if_group` is not "any event of this type" — it's "an event some other rule already tagged"

**What happened:** the first version of both Wazuh rules used:

```xml
sysmon_eid1_detections
```

assuming this meant "any Sysmon Event ID 1 (process creation) event."
It doesn't. `sysmon_eid1_detections` is a **group tag applied by specific
child rules** in the community Sysmon ruleset (e.g., a rule that only
fires on discovery commands like `net user`). A plain PowerShell launch,
or a plain `taskkill`, was never tagged with that group in the first
place — because no other rule had matched it yet — so neither of our
rules ever got a chance to evaluate the event. Both rules deployed
without error, loaded cleanly, and simply never fired. No error, no
warning — just silence, which is the most dangerous kind of detection
failure.

**The fix:** anchor to the underlying **base parser rule** for the
event type instead of an emergent group tag — in Wazuh's default
ruleset, the "Sysmon - Event 1: Process created" base rule (a
`level="0"` rule that exists purely so other rules can hook onto it)
fires unconditionally on every Sysmon EID1 event:

```xml
61603
```

**Takeaway:** when extending a community/vendor ruleset, verify whether
a `<group>` you're relying on is a **type tag** (applied to every event
of that kind) or an **outcome tag** (applied only when some other rule's
condition already matched). Confirm with `grep -r 'id="<base_rule_id>"'
/var/ossec/ruleset/rules/` before trusting a group name at face value.

## Lesson 2: real deployment surfaces real false positives Sigma fixtures can't predict

Two false positives appeared in production that weren't anticipated by
the synthetic fixtures, both resolved with narrowly-scoped exclusion
rules rather than loosening the original detection:

**A vendor application plugin dropping a driver DLL into a user's temp
folder** triggered an unrelated, pre-existing community rule for
"executable file dropped in a folder commonly used by malware." The
plugin (a legitimate EHR/clinical software component) was installing a
TWAIN scanner driver as part of normal operation. The exclusion was
scoped to the exact parent process image **and** the exact target
filename — not a blanket mute of the parent rule — so a genuinely
malicious process spoofing a similar filename would still alert.

**A printer driver's noisy internal logging** (a benign but
high-frequency error string logged by a network printer's Windows
driver) flooded the alert pipeline at a rate of hundreds of events per
minute, drowning real signal in the same stream. This required muting
**two** related rules — the base error rule and a separate frequency-
correlation rule that fires when the base rule repeats — since
suppressing only the first left the second still firing on top of it.
Both exclusions were scoped to the specific log provider name and event
ID, not to "all Windows application errors."

**Takeaway:** a rule that looks clean in CI can still generate real
noise the first week it runs against live telemetry — from firmware,
plugins, drivers, and other software nobody was thinking about when the
rule was written. Budget time after any real deployment to review the
first 1-2 weeks of alert volume and add narrow, evidence-based
exclusions — not to gut the rule's coverage.

## Lesson 3: validate with a live-fire test, not just a synthetic fixture pass

Both rules were confirmed working only after running a harmless,
deliberately-triggered real command on a test endpoint and watching for
the alert in the live Wazuh alert stream — the same two-step validation
(CI unit test + live fire) called out in the top-level README. The
synthetic fixture tests in `tests/` had already passed for both rules
before the `if_group` bug was found; passing fixtures alone did not
catch it, because the bug was in how the rule was *wired into* the real
ruleset, not in the rule's field-matching logic itself.

## Rule ID reference (Wazuh side, not shown elsewhere in this repo)

These IDs are specific to the local Wazuh deployment and are not part
of the portable Sigma rules — included here for completeness since this
file documents the real deployment, not just the Sigma-format artifacts.

| Wazuh rule ID | Purpose | Level |
|---|---|---|
| 100010 | Suspicious encoded/download-cradle PowerShell | 12 |
| 100011 | EDR agent tampering (stop/kill Bitdefender process) | 14 |
| 100012 | Exclusion: printer driver error spam (base rule) | 0 |
| 100013 | Exclusion: printer driver error spam (frequency correlation) | 0 |
