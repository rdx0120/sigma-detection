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

**Additional instances of the same pattern, found in the same
deployment window** (each resolved with the same narrow parent-image +
target-filename exclusion technique as above, not written up separately
since they teach nothing new): a browser engine component
self-extracting its own speech-recognition library, a browser
self-extracting its own accessibility library, a clinical EHR browser
integration tool unpacking its own bundled Python runtime, and a
Windows OS compatibility-database service (`PcaSvc`) running routine
shim-database maintenance via `sdbinst.exe`. See the rule ID table
below for the specific exclusions.

## Lesson 3: validate with a live-fire test, not just a synthetic fixture pass

Both rules were confirmed working only after running a harmless,
deliberately-triggered real command on a test endpoint and watching for
the alert in the live Wazuh alert stream — the same two-step validation
(CI unit test + live fire) called out in the top-level README. The
synthetic fixture tests in `tests/` had already passed for both rules
before the `if_group` bug was found; passing fixtures alone did not
catch it, because the bug was in how the rule was *wired into* the real
ruleset, not in the rule's field-matching logic itself.

## Lesson 4: match the artifact pattern, not the parent process, when the parent is expected to vary

**What happened:** a maximum-severity, mail-enabled community rule
("executable file dropped in a folder commonly used by malware") kept
firing on a specific throwaway file — `__PSScriptPolicyTest_<random>.ps1`
— from multiple, unrelated parent processes: a Windows diagnostics
host, a laptop vendor's companion application, and others expected to
recur with different parents over time.

That filename is a well-known, universal Windows artifact: any time
*any* process on *any* Windows machine invokes PowerShell, Windows
silently writes a throwaway script-policy-check file with that exact
naming pattern, runs it, and deletes it. It has nothing to do with
whatever triggered it — dozens of unrelated legitimate applications on
any endpoint can cause it.

**The wrong fix:** write a per-parent-process exclusion every time a
new application happens to trigger it (the same technique used for the
narrow, vendor-specific false positives in Lesson 2). This does not
scale — the parent will keep changing, and each new benign trigger
would require a new exclusion rule discovered only after it has already
sent an alert.

**The right fix:** exclude on the **artifact pattern itself**, with no
`parent`/`image` field constraint at all, since the pattern is what's
diagnostic — not the process that happened to cause it this time.

**Takeaway:** before writing a narrow, parent-scoped exclusion, check
whether the false-positive artifact is actually a *generic OS or
runtime behavior* rather than something specific to one vendor's
software. A generic behavior needs a generic, parent-agnostic
exclusion; a vendor-specific behavior needs a narrow, parent-scoped
one. Using the wrong technique for the wrong case either overblocks
(muting unrelated processes that happen to share a parent) or
underblocks (an endless stream of one-off exclusions that never
actually converges).

## Lesson 5: "no resolvable parent process" is not itself a suspicion signal — match the activation signature instead

**What happened:** two separate high-severity community rules
(T1055 — Process Injection) fired repeatedly on completely benign
desktop activity: `dllhost.exe` acting as a **COM Surrogate** (hosting
a shell extension or thumbnail handler) and `backgroundTaskHost.exe`
running a UWP app's background task. Both shared an identical
underlying signature in the raw Sysmon telemetry: `parentProcessGuid`
all-zero and `parentImage: "-"` — Sysmon could not resolve a parent
process at all.

This is expected, ordinary behavior: Windows' own COM/DCOM activation
infrastructure launches these processes directly, without a
traditional visible parent for Sysmon to walk back to. It is extremely
common on any modern desktop — thumbnail generation, background app
activity, and many built-in Windows features all go through this path.
A community rule treating "no resolvable parent" as inherently
suspicious will systematically false-positive on this class of
activity across the whole fleet.

**The wrong fix:** exclude on "parent is unresolved," full stop. That
would blind the detection to a genuinely orphaned *malicious* process —
process injection and several defense-evasion techniques deliberately
produce exactly this signature, which is why the underlying rule exists
at all. Muting on the absence of a parent throws away the entire point
of the rule.

**The right fix:** exclude on the **specific, well-known activation
command-line signature** for each legitimate COM/DCOM case instead —
`dllhost.exe` acting as a COM Surrogate always carries
`/Processid:{<GUID>}` in its command line; a UWP background task host
always carries `-ServerName:App.<package>.mca`. These are narrow,
specific, and do not match how a malicious process using process
injection would typically be invoked.

**Takeaway:** an "unresolved parent process" field is a legitimate,
valuable detection signal — don't discard it by excluding on it
directly. Instead, find the specific, narrow signature that
distinguishes the *known-benign* case that shares that field value,
and exclude on that signature. This preserves the rule's ability to
catch the same field pattern when it appears *without* the benign
signature attached.

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
| 100026 | Exclusion: known vendor self-extraction unpacker DLLs (Lesson 2) | 0 |
| 100027 | Exclusion: Windows universal PowerShell script-policy-test artifact, parent-agnostic (Lesson 4) | 0 |
| 100028 | Exclusion: routine PcaSvc-driven shim database maintenance (Lesson 2) | 0 |
| 100029 | Exclusion: dllhost.exe COM Surrogate activation, matched by activation signature not absent parent (Lesson 5) | 0 |
| 100030 | Exclusion: UWP background task host activation via COM, same reasoning as 100029 (Lesson 5) | 0 |
| 100031 | Exclusion: encoded PowerShell launched by the legitimate Atera RMM agent (own rule 100010's predicted, now-confirmed false positive) | 0 |
