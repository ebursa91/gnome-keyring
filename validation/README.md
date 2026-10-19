# OpenSession concurrency regression

Run against an explicitly selected daemon executable:

```sh
python3 validation/run-opensession.py --daemon /absolute/path/to/gnome-keyring-daemon
```

The default is 16 concurrent clients × 200 rounds. Each round creates a fresh
D-Bus connection, opens a valid `plain` Secret Service session, checks its reply,
closes the returned session, and closes the connection. `--algorithm dh` exercises
the AES/Diffie-Hellman path from the observed crash instead, using the public
group element 2 and checking the returned byte array. No credential items or
collections are created or read in either mode.

The runner compiles its C client using existing `gcc` and `pkg-config gio-2.0`.
It installs nothing. It creates its own `dbus-daemon` with **no activation service
directories** and a throwaway HOME, XDG directories and keyring control directory.
It does not inherit the real session bus address or user configuration. The daemon
and clients have a zero core-size limit. Children are stopped and reaped, and all
temporary data and logs are removed on completion, failure, SIGINT or SIGTERM.

Output is one JSON summary containing attempted calls, successful opens/closes,
failures, the daemon's exit status before cleanup, and `passed`. Exit code is zero
only when every expected call succeeds and the daemon remains alive. A negative
`daemon_exit` is a terminating signal (`-6` means SIGABRT). A failed test is
evidence of a regression; one passing run cannot establish that a race is absent.

Optional bounds:

```sh
python3 validation/run-opensession.py --daemon /absolute/path/to/gnome-keyring-daemon \
  --threads 16 --rounds 200 --timeout 90

python3 validation/run-opensession.py --daemon /absolute/path/to/gnome-keyring-daemon \
  --algorithm dh --threads 16 --rounds 200 --timeout 90
```

This follows the fresh-connection pattern of the public
[GNOME issue 190 reproducer](https://gitlab.gnome.org/GNOME/gnome-keyring/-/work_items/190#note_2851630).
The original attachment is
[opensession-race-clean.c](https://gitlab.gnome.org/-/project/1628/uploads/2a758a1afdb73e7e5c6baf5cf8d59c03/opensession-race-clean.c).
This functional test additionally checks the plain-session reply and `Close`.

## Disconnected-client lifecycle

```sh
python3 validation/run-client-lifecycle.py \
  --daemon /absolute/path/to/symbolized/gnome-keyring-daemon
```

This also uses its own empty home and non-activating bus. GDB inspects only the
daemon child it launches, comparing client names with the private bus's live
names. It checks normal sessions, two batches of connections closed before their
replies, and a deterministic late dispatch for a name proven absent. The latter
creates state through the daemon's normal helper, resumes dispatch and verifies
that the initial ownership check removes it. Finally it requests shutdown with
ownership lookups pending. All settled phases must return to the initial client
count with no stale names, and shutdown must be clean.

This test requires GDB and a symbolized build. It permits inspection of its own
temporary children without changing the machine's ptrace policy. It disables
debuginfod and never attaches to an existing desktop daemon.

## Package boundary

```sh
python3 validation/compare-package.py /path/to/original.pkg.tar.zst \
  /path/to/patched.pkg.tar.zst
```

This compares file bytes, modes, owners and symlink targets while allowing fresh
package metadata. Only `usr/bin/gnome-keyring-daemon` may differ.
