import hashlib
import importlib.util
from pathlib import Path

import contracting
import pytest
from contracting.client import ContractingClient
from contracting.compilation import whitelists

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = PROJECT_ROOT / "con_privacy_token.py"
HELPER_PATH = PROJECT_ROOT / "client_helper.py"
SUBMISSION_PATH = (
    Path(contracting.__file__).resolve().parent / "contracts" / "submission.s.py"
)


@pytest.fixture(scope="session", autouse=True)
def enable_sha3_and_whitelist():
    whitelists.ALLOWED_BUILTINS.update({"hashlib", "decimal"})

    if not hasattr(hashlib, "sha3"):
        def _sha3(data):
            if isinstance(data, str):
                data = data.encode("utf-8")
            return hashlib.sha3_256(data).hexdigest()

        setattr(hashlib, "sha3", _sha3)


@pytest.fixture(scope="session")
def helper_module():
    spec = importlib.util.spec_from_file_location("client_helper_tests", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client():
    client = ContractingClient(signer="operator", metering=False)
    client.flush()
    client.set_submission_contract(str(SUBMISSION_PATH))
    return client


@pytest.fixture
def contract(client):
    code = CONTRACT_PATH.read_text()
    client.submit(code, name="con_privacy_token", owner=None)
    return client.get_contract("con_privacy_token")
