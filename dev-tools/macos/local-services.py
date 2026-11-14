#!/usr/bin/env python3
"""Start, stop, or inspect the two local native services."""

import argparse
import json
import os
from pathlib import Path
import plistlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "stop", "status"), default="start", nargs="?")
    action = parser.parse_args().action
    root = Path(__file__).resolve().parents[2]
    build = root / "build-macos"
    data = build / "metal-data"
    java = os.environ.get("JAVA_HOME", "/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")
    servers_config = root / "dev-tools/macos/servers.local.json"
    if not servers_config.is_file():
        servers_config = servers_config.with_name("servers.example.json")
    services = {
        "heavydb": [
            "/usr/bin/env", f"JAVA_HOME={java}", "JAVA_TOOL_OPTIONS=-Dheavyai.listen.address=127.0.0.1",
            f"PATH={java}/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            str(build / "bin/heavydb"), "--data", str(data), "--cpu-only", "--enable-metal",
            "--listen-address", "127.0.0.1", "--cpu-buffer-mem-bytes", "4294967296",
            "--num-executors", "2", "--cpu-threads", "8", "--calcite-max-mem", "1024",
            "--libgeos-so-filename", "/opt/homebrew/opt/geos/lib/libgeos_c.dylib",
            "--allowed-import-paths", json.dumps([str(build)]),
            "--log-severity-clog", "INFO", "--log-severity", "INFO",
        ],
        "web": [
            str(build / "bin/heavy_web_server"), "--host", "127.0.0.1", "--port", "6273",
            "--backend-url", "http://127.0.0.1:6278", "--binary-backend-url", "http://127.0.0.1:6276",
            "--frontend", str(root / "immerse-src/dist"),
            "--servers-json", str(servers_config), "--data", str(data),
        ],
    }
    if action == "start" and not (data / "catalogs/system_catalog").is_file():
        parser.error(f"Initialize {data} with initheavy before starting services")
    names = ("web", "heavydb") if action == "stop" else ("heavydb", "web")
    for name in names:
        label = f"local.heavyai.metal.{name}"
        state = subprocess.run(["launchctl", "list", label], text=True, capture_output=True)
        if action == "status":
            print(state.stdout if state.returncode == 0 else f"{label}: not loaded")
        elif action == "stop" and state.returncode == 0:
            subprocess.run(["launchctl", "bootout", "--wait", f"gui/{os.getuid()}/{label}"], check=True)
        elif action == "start" and state.returncode != 0:
            log = str(build / f"{name}-console.log")
            job = dict(Label=label, ProgramArguments=services[name], RunAtLoad=True,
                       KeepAlive=True, StandardOutPath=log, StandardErrorPath=log)
            if name == "heavydb":
                job["SoftResourceLimits"] = {"NumberOfFiles": 4096}
            definition = build / f"{label}.plist"
            definition.write_bytes(plistlib.dumps(job))
            subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(definition)], check=True)
    if action == "start":
        print("Native services loaded. Open http://127.0.0.1:6273 after startup.")


if __name__ == "__main__":
    main()
