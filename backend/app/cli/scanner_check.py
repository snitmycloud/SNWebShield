"""Verify Windows-to-VM analysis with synthetic headers, never a target request."""
import json
from uuid import uuid4

from app.core.config import settings
from app.services.header_analyzer import analyze
from app.services.remote_assessment_runtime import VERSION, ssh_exchange, validate_execution


def main():
    image = settings.assessment_remote_image_id
    if not image:
        raise SystemExit("Configure ASSESSMENT_REMOTE_IMAGE_ID first.")
    token = None
    try:
        check = ssh_exchange("check", None, lambda: True, 10)
        if check != {"runner": VERSION, "image_id": image}:
            raise ValueError("remote_preflight_failed")
        data = {"https": True, "status": 200, "headers": {"x-content-type-options": "nosniff"}}
        token = uuid4().hex
        reply = ssh_exchange("run", {"id": token, "data": data}, lambda: True, 22)
        if reply.get("error") or reply.get("analysis") != analyze(data):
            raise ValueError("remote_analysis_contract_failed")
        execution = validate_execution(reply.get("execution"), token, image)
    except Exception as error:
        if token:
            try:
                ssh_exchange("cleanup", token, lambda: True, 10)
            except Exception:
                pass  # Original failure remains visible; never claim confirmed cleanup.
        raise SystemExit("Scanner check failed: " + str(error)) from None
    print(json.dumps({"passed": True, "target_requests": 0, "execution": execution}, indent=2))


if __name__ == "__main__":
    main()
