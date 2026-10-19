# GNOME Keyring 51.1 backport validation

Validated on 2026-10-19 with GLib 2.90.1, glibc 2.44+r50 and GCC 16.2.1.
The final daemon uses Arch's compiler/linker flags, PIE, LTO, BIND_NOW,
stack protection and fortified libc calls. Its build ID is
`65b56b6891299549068cb1021e569d9c28688197`.

All runtime regression checks used private buses with activation directories
omitted, temporary empty HOME/XDG/control directories, core dumps disabled and
child-process cleanup. No desktop keyring was used for these tests.

| Check | Observed result |
| --- | --- |
| Stock 51.1, 3,200 plain sessions | SIGABRT; 901 opens, 898 closes, 2,302 failed rounds |
| Stock 51.1, 3,200 DH/AES sessions | Passed in this run; the race is intermittent |
| Final build, 3,200 plain sessions | All opened and closed; zero failures; daemon survived |
| Final build, 3,200 DH/AES sessions | All opened and closed; zero failures; daemon survived |
| Upstream Meson suite, final backport build | 63 targets passed, zero failed; the PAM target internally skipped its 10 cases because test PAM configuration was absent |
| C lifecycle regression on upstream main | Unpatched main deterministically retained a late-created session; patched main passed all three cases across ten consecutive runs and again after restoring the baseline comparison |
| Original two-commit proposal, disconnected callers | Retained 30 stale names after two 12,800-call batches; also failed the deterministic absent-caller check |
| Final build, 3,200 normal sessions | Client table returned to its initial count; no stale callers |
| Final build, two 3,200-call disconnect batches | Client table returned to its initial count; no stale callers |
| Final build, deterministic late dispatch | Absent caller created state immediately; state disappeared after dispatch resumed |
| Final build, shutdown with pending lookups | Clean exit, status 0 |
| Final local package vs original Arch archive | Same 332 payload entries; only the daemon executable differs, including content/mode/owner/link comparisons |

The signed original Arch package was verified before packaging. The local
package is `1:51.1-1.2`; it retains the original service units, D-Bus activation
files, PAM modules, translations, documentation and install hooks byte for byte.
It is a locally built package, not a signed Arch release.

Two independent reviews inspected the source and installation boundary. Review
identified and prompted correction of stale-client cleanup and missing compiler
hardening in the initial build. The in-tree lifecycle test then exposed queued
registration after disposal, which now returns before using the cleared connection.
The final source and packaging
review reported no remaining blockers.

This establishes the tested regression behavior, not that every future keyring
failure or every credential client's behavior is fixed. The original upstream
proposal remains unmerged; this branch adds its own lifecycle cleanup and tests.
