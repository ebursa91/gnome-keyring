#!/usr/bin/env python3
"""Assert disconnected clients are removed, using ONLY an isolated test daemon.

Requires a symbolized daemon, GCC, GDB, GLib development headers, gdbus and
dbus-daemon. GDB attaches only to the child created here, reads client names,
and calls its table helpers. The deterministic case calls the PKCS#11-session
helper for a unique bus name proven absent, simulating dispatch after disconnect.
No host daemon, configuration, keyring file or credential is accessed.
"""

import argparse
import ast
import ctypes
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


ABSENT = ":1.4294967000"
LIBC = ctypes.CDLL(None)


def child_setup():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Permit GDB, another child of this harness, to inspect this test child.
    # Do not change the machine's ptrace policy.
    if LIBC.prctl(0x59616D61, ctypes.c_ulong(-1).value, 0, 0, 0):
        raise RuntimeError("test_child_ptracer_setup_failed")


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


def bus_call(env, method, *arguments):
    return subprocess.check_output(
        ["gdbus", "call", "--address", env["DBUS_SESSION_BUS_ADDRESS"],
         "--dest", "org.freedesktop.DBus", "--object-path", "/org/freedesktop/DBus",
         "--method", "org.freedesktop.DBus." + method, *arguments],
        text=True, env=env, timeout=5).strip()


def inspect_clients(root, env, daemon, inject=False):
    """Read only test client names; never inspect stored secret values."""
    command = root / "inspect.gdb"
    command.write_text(
        "set pagination off\nset confirm off\nset debuginfod enabled off\n"
        f"attach {daemon.pid}\n" +
        "python\n"
        "import gdb, json\n"
        "try:\n"
        "    service=gdb.parse_and_eval('secrets_service')\n"
        "    int(service)\n"
        "except gdb.error:\n"
        "    service=gdb.parse_and_eval(\"*(GkdSecretService **)&'secrets_service.lto_priv.0'\")\n"
        "gdb.set_convenience_variable('service',service)\n" +
        (f"gdb.parse_and_eval('(void *)gkd_secret_service_get_pkcs11_session($service, \"{ABSENT}\")')\n"
         if inject else "") +
        "n=int(gdb.parse_and_eval('(unsigned int)g_hash_table_size($service->clients)'))\n"
        "keys=gdb.parse_and_eval('(char **)g_hash_table_get_keys_as_array($service->clients, (void *)0)')\n"
        "names=[keys[i].string() for i in range(n)]\n"
        "gdb.parse_and_eval('(void)g_free((void *)'+str(int(keys))+')')\n"
        "print('LIFECYCLE_CLIENTS='+json.dumps(sorted(names)))\n"
        "end\ndetach\n", encoding="utf-8")
    completed = subprocess.run(
        ["gdb", "-q", "--batch", "-x", str(command)], env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
    lines = [line for line in completed.stdout.splitlines()
             if line.startswith("LIFECYCLE_CLIENTS=")]
    if completed.returncode or len(lines) != 1:
        raise RuntimeError("private_child_gdb_inspection_failed: " + completed.stdout[-1500:])
    return json.loads(lines[0].split("=", 1)[1])


def snapshot(root, env, daemon, label, inject=False):
    if daemon.poll() is not None:
        raise RuntimeError("test_daemon_exited")
    # The ListNames query creates a short-lived inspector connection. It sends
    # no Secret Service request and is gone before the client-table inspection.
    live = ast.literal_eval(bus_call(env, "ListNames"))[0]
    time.sleep(0.2)
    clients = inspect_clients(root, env, daemon, inject)
    result = {"phase": label, "clients": clients, "client_count": len(clients),
              "live_names": live, "stale_clients": sorted(set(clients) - set(live))}
    print(json.dumps(result, sort_keys=True), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemon", required=True, type=Path)
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if not 1 <= args.threads <= 128 or not 1 <= args.rounds <= 100000:
        parser.error("threads must be 1..128; rounds must be 1..100000")
    if not 0 < args.timeout <= 300:
        parser.error("timeout must be greater than zero and at most 300 seconds")
    daemon_path = args.daemon.resolve(strict=True)
    if not daemon_path.is_file() or not os.access(daemon_path, os.X_OK):
        parser.error("--daemon must identify an executable test build")
    for executable in ("gcc", "pkg-config", "dbus-daemon", "gdbus", "gdb"):
        if shutil.which(executable) is None:
            parser.error("missing required executable: " + executable)
    signal.signal(signal.SIGTERM, interrupted)
    children = []
    summary = {"phase": "summary", "passed": False}
    source = Path(__file__).resolve().parent
    try:
        with tempfile.TemporaryDirectory(prefix="gkd-lifecycle-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                   "DEBUGINFOD_URLS": ""}
            for key in ("HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR",
                        "XDG_CACHE_HOME", "XDG_STATE_HOME", "GNOME_KEYRING_CONTROL"):
                directory = root / key.lower()
                directory.mkdir(mode=0o700)
                env[key] = str(directory)
            env["DEBUGINFOD_CACHE_PATH"] = str(root / "unused-debug-cache")
            env["GNOME_KEYRING_TEST_PATH"] = env["XDG_DATA_HOME"]
            flags = shlex.split(subprocess.check_output(
                ["pkg-config", "--cflags", "--libs", "gio-2.0"], env=env, text=True, timeout=10))
            normal, abortive = root / "normal-client", root / "abortive-client"
            for output, filename in ((normal, "opensession-client.c"),
                                     (abortive, "abortive-client.c")):
                subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                                "-o", str(output), str(source / filename), *flags],
                               check=True, env=env, timeout=30)
            config = root / "bus.conf"
            config.write_text(
                '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" '
                '"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
                '<busconfig><type>session</type>'
                f'<listen>unix:path={root / "bus.socket"}</listen><auth>EXTERNAL</auth>'
                f'<policy context="default"><allow user="{os.getuid()}"/>'
                '<allow own="*"/><allow send_destination="*"/>'
                '<allow receive_sender="*"/></policy></busconfig>', encoding="utf-8")
            # No service directories or includes: this bus cannot activate host services.
            def spawn(command, **kwargs):
                process = subprocess.Popen(command, env=env, start_new_session=True,
                                           preexec_fn=child_setup, **kwargs)
                children.append(process)
                return process
            with (root / "bus.log").open("w") as bus_log, \
                    (root / "daemon.log").open("w") as daemon_log:
                try:
                    bus = spawn(["dbus-daemon", f"--config-file={config}", "--nofork",
                                 "--nopidfile", "--print-address=1"],
                                stdout=subprocess.PIPE, stderr=bus_log, text=True)
                    with selectors.DefaultSelector() as selector:
                        selector.register(bus.stdout, selectors.EVENT_READ)
                        if not selector.select(timeout=5):
                            raise RuntimeError("private_bus_startup_timeout")
                        address = bus.stdout.readline().strip()
                    if not address.startswith(f"unix:path={root}/"):
                        raise RuntimeError("private_bus_startup_failed")
                    env["DBUS_SESSION_BUS_ADDRESS"] = address
                    daemon = spawn([str(daemon_path), "--foreground", "--components=secrets,pkcs11",
                                    "--control-directory=" + env["GNOME_KEYRING_CONTROL"]],
                                   stdin=subprocess.DEVNULL, stdout=daemon_log, stderr=daemon_log)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if daemon.poll() is not None:
                            raise RuntimeError("test_daemon_exited_at_startup")
                        ready = subprocess.run([str(normal), "--ready", address], env=env,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                               timeout=2)
                        if ready.returncode == 0:
                            break
                        time.sleep(0.05)
                    else:
                        raise RuntimeError("test_daemon_readiness_timeout")
                    time.sleep(0.5)
                    baseline = snapshot(root, env, daemon, "baseline")
                    if baseline["stale_clients"]:
                        raise RuntimeError("stale_clients_at_baseline")
                    snapshots = []
                    for phase, executable in (("normal", normal), ("abortive-1", abortive),
                                              ("abortive-2", abortive)):
                        command = [str(executable), address, str(args.threads), str(args.rounds)]
                        if executable == normal:
                            command.append("plain")
                        client = spawn(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                        stdout, _ = client.communicate(timeout=args.timeout)
                        result = json.loads(stdout)
                        print(json.dumps({"phase": phase + "-calls", **result}), flush=True)
                        if client.returncode or result.get("failures"):
                            raise RuntimeError(phase + "_client_failed")
                        time.sleep(2)
                        snapshots.append(snapshot(root, env, daemon, phase))
                    if bus_call(env, "NameHasOwner", ABSENT) != "(false,)":
                        raise RuntimeError("synthetic_name_unexpectedly_exists")
                    injected = snapshot(root, env, daemon, "synthetic-immediate", inject=True)
                    if ABSENT not in injected["clients"]:
                        raise RuntimeError("synthetic_dispatch_did_not_create_client")
                    time.sleep(2)
                    snapshots.append(snapshot(root, env, daemon, "synthetic-drained"))
                    # Finish while another bounded client burst can have owner lookups pending.
                    pending = spawn([str(abortive), address, "8", "50"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(0.05)
                    daemon.send_signal(signal.SIGTERM)
                    exit_code = daemon.wait(timeout=5)
                    stop(pending)
                    summary["shutdown_exit"] = exit_code
                    summary["checked_phases"] = len(snapshots)
                    summary["stale_clients"] = sorted({name for item in snapshots
                                                       for name in item["stale_clients"]})
                    summary["passed"] = (exit_code == 0 and not summary["stale_clients"] and
                                         all(item["client_count"] == baseline["client_count"]
                                             for item in snapshots))
                finally:
                    for process in reversed(children):
                        stop(process)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
    except KeyboardInterrupt:
        summary["error"] = "interrupted"
    finally:
        for process in reversed(children):
            stop(process)
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
