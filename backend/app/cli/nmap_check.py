"""Fixed infrastructure self-test; scans only the existing scanner VM's TCP 80/443."""
import json
import sys
from uuid import uuid4

from app.core.config import settings
from app.services import nmap_policy as policy
from app.services.nmap_runtime import exchange, validate_execution


def main():
    if len(sys.argv) != 1: raise SystemExit("This self-test accepts no target or command arguments.")
    image = settings.assessment_nmap_image_id
    if not image: raise SystemExit("Configure the approved Nmap image ID first.")
    token = None
    try:
        if exchange("check", None, lambda: True, 8) != {"runner": policy.VERSION, "image_id": image, "ports": list(policy.PORTS)}:
            raise ValueError("nmap_preflight_failed")
        token = uuid4().hex
        target = {"host": "vm.snwebshield.example", "ip": "57.159.27.58", "dns_addresses": ["57.159.27.58"]}
        result = exchange("run", {"id": token, "target": target}, lambda: True, 32)
        if result.get("error") or result.get("analysis") != policy.analysis(result.get("states")):
            raise ValueError("nmap_result_invalid")
        execution = validate_execution(result.get("execution"), token, image, target["ip"])
    except Exception as error:
        if token:
            try: exchange("cleanup", token, lambda: True, 8)
            except Exception: pass
        raise SystemExit("Nmap self-test failed: " + str(error)) from None
    print(json.dumps({"passed": True, "target_kind": "existing_VM_only", "ports": list(policy.PORTS),
                      "states": result["states"], "execution": execution}, indent=2))


if __name__ == "__main__": main()
