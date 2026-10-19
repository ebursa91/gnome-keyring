# GNOME Keyring 51.1 backport validation

Validated on 2026-10-19 with GLib 2.90.1, glibc 2.44+r50 and GCC 16.2.1.
The final daemon uses Arch's compiler/linker flags, PIE, LTO, BIND_NOW,
stack protection and fortified libc calls. Its build ID is
`5f2a8c580290c1a3a887020a61c05637cce249e7`.

All runtime regression checks used private buses with activation directories
omitted, temporary empty HOME/XDG/control directories, core dumps disabled and
child-process cleanup. No desktop keyring was used for these tests.

| Check | Observed result |
| --- | --- |
| Stock 51.1, 3,200 plain sessions | SIGABRT; 901 opens, 898 closes, 2,302 failed rounds |
| Stock 51.1, 3,200 DH/AES sessions | Passed in this run; the race is intermittent |
| Final build, 3,200 plain sessions | All opened and closed; zero failures; daemon survived |
| Final build, 3,200 DH/AES sessions | All opened and closed; zero failures; daemon survived |
| Upstream Meson suite, final build | 62 targets passed, zero failed; the PAM target internally skipped its 10 cases because test PAM configuration was absent |
| Original two-commit proposal, disconnected callers | Retained 30 stale names after two 12,800-call batches; also failed the deterministic absent-caller check |
| Final build, 3,200 normal sessions | Client table returned to its initial count; no stale callers |
| Final build, two 3,200-call disconnect batches | Client table returned to its initial count; no stale callers |
| Final build, deterministic late dispatch | Absent caller created state immediately; state disappeared after dispatch resumed |
| Final build, shutdown with pending lookups | Clean exit, status 0 |
| Final local package vs original Arch archive | Same 332 payload entries; only the daemon executable differs, including content/mode/owner/link comparisons |

The signed original Arch package was verified before packaging. The local
package is `1:51.1-1.1`; it retains the original service units, D-Bus activation
files, PAM modules, translations, documentation and install hooks byte for byte.
It is a locally built package, not a signed Arch release.

Two independent reviews inspected the source and installation boundary. Review
identified and prompted correction of both the stale-client cleanup issue and
missing compiler hardening in the initial build. The final source and packaging
review reported no remaining blockers.

This establishes the tested regression behavior, not that every future keyring
failure or every credential client's behavior is fixed. The original upstream
proposal remains unmerged; this branch adds its own lifecycle cleanup and tests.
