#!/usr/bin/env python3
import subprocess
import json
import base64
import time
import sys

import os

DEFAULT_VM = os.environ.get("VM", "win10-ltsc")

def qemu_agent(cmd_dict, vm=None):
    if vm is None:
        vm = DEFAULT_VM
    cmd = ["virsh", "-c", "qemu:///system", "qemu-agent-command", vm, json.dumps(cmd_dict)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"virsh error: {p.stderr.strip()}")
    return json.loads(p.stdout)

def run_powershell(ps_command, timeout=30):
    # Encode command to avoid escape issues: powershell -EncodedCommand
    encoded = base64.b64encode(ps_command.encode('utf-16le')).decode('ascii')
    payload = {
        "execute": "guest-exec",
        "arguments": {
            "path": "powershell.exe",
            "arg": ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            "capture-output": True
        }
    }
    res = qemu_agent(payload)
    pid = res["return"]["pid"]

    start = time.time()
    while time.time() - start < timeout:
        status_payload = {
            "execute": "guest-exec-status",
            "arguments": {"pid": pid}
        }
        st = qemu_agent(status_payload)["return"]
        if st["exited"]:
            out = base64.b64decode(st.get("out-data", "")).decode("utf-8", errors="replace")
            err = base64.b64decode(st.get("err-data", "")).decode("utf-8", errors="replace")
            return st["exitcode"], out, err
        time.sleep(0.5)
    raise TimeoutError("Execution timed out")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        cmd_str = "Get-ComputerInfo | Select-Object OsName, OsVersion"
    else:
        cmd_str = " ".join(sys.argv[1:])
    
    code, out, err = run_powershell(cmd_str)
    if out:
        print(out)
    if err:
        print("STDERR:", err, file=sys.stderr)
    sys.exit(code)
