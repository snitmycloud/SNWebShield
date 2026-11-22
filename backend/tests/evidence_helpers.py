from io import BytesIO
from PIL import Image


def png():
    out = BytesIO(); Image.new("RGB", (20, 20), "white").save(out, format="PNG")
    return out.getvalue()


def attach_review(client, authorization_id, headers=None):
    options = {} if headers is None else {"headers": headers}
    upload_headers = {**(headers or {}), "X-Evidence-Filename": "signed-test.png", "Content-Type": "application/octet-stream"}
    response = client.post(f"/api/v1/authorizations/{authorization_id}/evidence", content=png(), headers=upload_headers)
    assert response.status_code == 201, response.text
    key = response.json()["id"]
    assert client.get(f"/api/v1/evidence/{key}/download", **options).status_code == 200
    revision = client.get(f"/api/v1/authorizations/{authorization_id}/evidence", **options).json()["revision"]
    review = client.post(f"/api/v1/authorizations/{authorization_id}/evidence/reviews", json={
        "revision": revision, "decision": "accepted", "inspected": True,
        "comment": "Inspected synthetic document and verified the complete permission scope.",
    }, **options)
    assert review.status_code == 201, review.text
    return key
