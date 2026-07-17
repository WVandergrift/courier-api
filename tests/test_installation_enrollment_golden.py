"""Golden-vector parity tests for the installation enrollment protocol.

``tests/data/installation-enrollment-v1-golden.json`` is a vendored copy of the
canonical fixture at ``ember-core/docs/data/installation-enrollment-v1-golden.json``.
The same vectors run against the Ember app's TypeScript builders and the
firmware message builders, so a divergence in any implementation fails one of
the three suites. Update the ember-core copy first, then refresh this one.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from app.ember_identity import enrollment_message, key_thumbprint
from app.ember_installation_documents import installation_document_message

GOLDEN = json.loads(
    (Path(__file__).parent / "data" / "installation-enrollment-v1-golden.json").read_text()
)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_fixture_is_internally_consistent():
    public_key = base64.urlsafe_b64decode(GOLDEN["clientPublicKey"] + "==")
    assert _b64u(hashlib.sha256(public_key).digest()) == GOLDEN["clientKeyThumbprint"]

    tag_key = bytes.fromhex(GOLDEN["tagKeyHex"])
    proof = hmac.new(tag_key, GOLDEN["nfcBleProofMessage"].encode(), hashlib.sha256).digest()
    assert _b64u(proof) == GOLDEN["tagProof"]

    assert GOLDEN["nfcBleProofMessage"] == (
        "ember-nfc-ble-proof/v1\n{proofMethod}\n{controllerId}\n{tagId}\n"
        "{challengeId}\n{serverNonce}\n{clientPublicKey}"
    ).format(**GOLDEN)


def test_enrollment_message_matches_golden_vector():
    assert enrollment_message(
        GOLDEN["proofMethod"],
        GOLDEN["challengeId"],
        GOLDEN["controllerId"],
        GOLDEN["tagId"],
        GOLDEN["clientKeyThumbprint"],
        GOLDEN["serverNonce"],
    ) == GOLDEN["courierEnrollmentMessage"].encode("utf-8")


def test_key_thumbprint_matches_golden_vector():
    assert key_thumbprint(GOLDEN["clientPublicKey"]) == GOLDEN["clientKeyThumbprint"]


def test_installation_document_message_matches_golden_vector():
    document = GOLDEN["installationDocument"]
    assert installation_document_message(
        document["action"],
        document["installationId"],
        document["memberId"],
        document["documentKey"],
        document["expectedRevision"],
        document["payloadDigest"],
        document["contentType"],
        document["requestedAt"],
    ) == document["message"].encode("utf-8")
