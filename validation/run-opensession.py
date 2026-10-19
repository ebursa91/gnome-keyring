#!/usr/bin/env python3
"""Run ordinary OpenSession/Close calls against an isolated supplied daemon."""

import argparse
import json
import os
from pathlib import Path
import resource
import selectors
import shlex
import shutil
import signal
import subprocess
import tempfile
import time


def no_core():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True, type=Path,
                        help="daemon executable to test; never discovers a session daemon")
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--algorithm", choices=("plain", "dh"), default="plain")
    parser.add_argument("--timeout", type=float, default=90,
                        help="maximum client runtime in seconds")
    args = parser.parse_args()
    daemon_path = args.daemon.resolve(strict=True)
    if not daemon_path.is_file() or not os.access(daemon_path, os.X_OK):
        parser.error("--daemon must name an executable file")
    if not 1 <= args.threads <= 128 or not 1 <= args.rounds <= 100000:
        parser.error("threads must be 1..128 and rounds must be 1..100000")
    if not 0 < args.timeout <= 3600:
        parser.error("timeout must be greater than zero and at most 3600 seconds")
    for executable in ("gcc", "pkg-config", "dbus-daemon"):
        if shutil.which(executable) is None:
            parser.error(f"required existing executable is unavailable: {executable}")

    signal.signal(signal.SIGTERM, interrupted)
    children = []
    result = {"algorithm": args.algorithm, "calls": 0, "opened": 0, "closed": 0, "failures": 0,
              "expected_calls": args.threads * args.rounds,
              "daemon_alive": False, "daemon_exit": None, "passed": False}
    daemon = None
    bus = None
    try:
        with tempfile.TemporaryDirectory(prefix="gkd-session-check-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            directories = {name: root / name for name in
                           ("home", "config", "data", "cache", "state", "runtime", "control")}
            for directory in directories.values():
                directory.mkdir(mode=0o700)
            # Deliberately do not inherit DBUS_*, HOME, XDG_*, keyring variables,
            # credentials or user configuration from the parent environment.
            env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                   "HOME": str(directories["home"]),
                   "XDG_CONFIG_HOME": str(directories["config"]),
                   "XDG_DATA_HOME": str(directories["data"]),
                   "XDG_CACHE_HOME": str(directories["cache"]),
                   "XDG_STATE_HOME": str(directories["state"]),
                   "XDG_RUNTIME_DIR": str(directories["runtime"]),
                   "GNOME_KEYRING_CONTROL": str(directories["control"])}
            flags = subprocess.check_output(
                ["pkg-config", "--cflags", "--libs", "gio-2.0"],
                text=True, env=env, timeout=10)
            client_path = root / "opensession-client"
            subprocess.run(
                ["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-o", str(client_path), str(Path(__file__).with_name("opensession-client.c")),
                 *shlex.split(flags)], check=True, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)

            config = root / "bus.conf"
            config.write_text(
                '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"\n'
                ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
                '<busconfig><type>session</type>'
                f'<listen>unix:path={root / "bus.socket"}</listen>'
                '<auth>EXTERNAL</auth><policy context="default">'
                f'<allow user="{os.getuid()}"/>'
                '<allow own="*"/><allow send_destination="*"/>'
                '<allow receive_sender="*"/></policy></busconfig>\n', encoding="utf-8")
            # No servicedir, standard_session_servicedirs, include or includedir.
            # Bus activation therefore cannot launch the host's real daemon.
            with (root / "bus.log").open("w") as bus_log, \
                    (root / "daemon.log").open("w") as daemon_log:
                try:
                    bus = subprocess.Popen(
                        ["dbus-daemon", f"--config-file={config}", "--nofork",
                         "--nopidfile", "--print-address=1"], env=env,
                        stdout=subprocess.PIPE, stderr=bus_log, text=True,
                        start_new_session=True, preexec_fn=no_core)
                    children.append(bus)
                    with selectors.DefaultSelector() as selector:
                        selector.register(bus.stdout, selectors.EVENT_READ)
                        if not selector.select(timeout=5):
                            raise RuntimeError("private_bus_startup_timeout")
                        bus_address = bus.stdout.readline().strip()
                    if not bus_address:
                        raise RuntimeError("private_bus_startup_failed")
                    if not bus_address.startswith(f"unix:path={root}/"):
                        raise RuntimeError("unexpected_private_bus_address")
                    env["DBUS_SESSION_BUS_ADDRESS"] = bus_address
                    daemon = subprocess.Popen(
                        [str(daemon_path), "--foreground", "--components=secrets,pkcs11",
                         f'--control-directory={directories["control"]}'],
                        env=env, stdin=subprocess.DEVNULL, stdout=daemon_log,
                        stderr=daemon_log, start_new_session=True, preexec_fn=no_core)
                    children.append(daemon)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if daemon.poll() is not None:
                            raise RuntimeError("daemon_exited_during_startup")
                        ready = subprocess.run(
                            [str(client_path), "--ready", bus_address], env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=2, preexec_fn=no_core)
                        if ready.returncode == 0:
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("daemon_readiness_timeout")

                    client = subprocess.Popen(
                        [str(client_path), bus_address, str(args.threads), str(args.rounds), args.algorithm],
                        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, text=True,
                        start_new_session=True, preexec_fn=no_core)
                    children.append(client)
                    stdout, _ = client.communicate(timeout=args.timeout)
                    result.update(json.loads(stdout))
                    # Give an abort already in progress time to reach waitpid.
                    time.sleep(0.1)
                    result["daemon_exit"] = daemon.poll()
                    result["daemon_alive"] = daemon.poll() is None
                    result["passed"] = (
                        client.returncode == 0 and result["daemon_alive"] and
                        result["calls"] == result["expected_calls"] and
                        result["opened"] == result["expected_calls"] and
                        result["closed"] == result["expected_calls"] and
                        result["failures"] == 0)
                finally:
                    # Reap the entire groups we created before deleting their
                    # private runtime/config/data directories and bounded logs.
                    if daemon is not None:
                        result["daemon_exit"] = daemon.poll()
                        result["daemon_alive"] = daemon.poll() is None
                    for process in reversed(children):
                        stop(process)
                    if bus is not None and bus.stdout:
                        bus.stdout.close()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = (str(error) if isinstance(error, RuntimeError)
                           else type(error).__name__)
    except KeyboardInterrupt:
        result["error"] = "interrupted"
    finally:
        # Also covers interruptions before the normal cleanup block is entered.
        for process in reversed(children):
            stop(process)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
