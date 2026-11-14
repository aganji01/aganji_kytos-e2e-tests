"""Helpers shared by the security fuzz / crafted-input e2e tests.

Used by the FUZZ-xx and REST-xx rows of the shared test-case tracker.

Schemathesis is imported with importorskip so the rest of the suite keeps
working in an environment where it is not installed. Pinned to
``schemathesis==3.39.16`` (Schemathesis 4.x needs pytest>=8.4, but this repo
pins pytest==8.2.0).
"""
import os
import pathlib

import pytest
import requests

schemathesis = pytest.importorskip(
    "schemathesis",
    reason="schemathesis is not installed (pip install schemathesis==3.39.16)",
)

from hypothesis import HealthCheck, settings  # noqa: E402
from schemathesis import DataGenerationMethod  # noqa: E402
from schemathesis.checks import not_a_server_error  # noqa: E402

from tests.security_checks import LEAK_PATTERNS, find_leaks  # noqa: E402,F401

CONTROLLER = "127.0.0.1"
KYTOS_URL = f"http://{CONTROLLER}:8181"
STATUS_URL = f"{KYTOS_URL}/api/kytos/core/status/"

# Seconds to wait for a single fuzzed request. A hang is itself a finding
# (requests raises Timeout and the test fails).
REQUEST_TIMEOUT = 15


def no_internal_details_leaked(ctx, response, case):
    """Schemathesis check: error bodies must not expose internals.

    ``ctx`` is the CheckContext Schemathesis passes first (unused here).
    """
    leaks = find_leaks(response.text)
    if leaks:
        raise AssertionError(
            f"{case.method} {case.formatted_path} leaked internal details "
            f"({', '.join(leaks)}): {response.text[:300]!r}"
        )


CHECKS = (not_a_server_error, no_internal_details_leaked)


def napp_spec_path(napp, username="kytos"):
    """Path of a NApp's openapi.yml inside the Kytos container.

    Follows the same NAPPS_PATH / VIRTUAL_ENV logic as kytos-init.sh. Each
    NApp loads this very file to validate requests, so fuzzing from it
    tests what the NApp actually enforces.
    """
    base = os.environ.get("NAPPS_PATH") or os.environ.get("VIRTUAL_ENV") or ""
    return pathlib.Path(
        f"{base}/var/lib/kytos/napps/{username}/{napp}/openapi.yml")


def load_napp_schema(napp, base_url=KYTOS_URL, username="kytos"):
    """Load a NApp's OpenAPI spec for positive and negative generation."""
    path = napp_spec_path(napp, username)
    if not path.is_file():
        raise FileNotFoundError(
            f"OpenAPI spec for {username}/{napp} not found at {path}. "
            "Set NAPPS_PATH if NApps are installed elsewhere."
        )
    return schemathesis.from_path(
        str(path),
        base_url=base_url,
        data_generation_methods=[
            DataGenerationMethod.positive,
            DataGenerationMethod.negative,
        ],
    )


def fuzz_settings():
    """Hypothesis settings for the fuzz tests.

    derandomize makes every run reproduce the same inputs, so --reruns and
    CI regressions are meaningful. Raise the example count with the
    FUZZ_MAX_EXAMPLES environment variable for a deeper manual run.
    """
    return settings(
        max_examples=int(os.environ.get("FUZZ_MAX_EXAMPLES", "50")),
        deadline=None,
        derandomize=True,
        database=None,
        suppress_health_check=list(HealthCheck),
    )


def assert_controller_running():
    """The controller must survive whatever the fuzzer sent."""
    response = requests.get(STATUS_URL, timeout=10)
    assert response.status_code == 200, response.text
    assert response.json()["response"] == "running", response.text


def run_case(case):
    """Send one generated request and apply the security checks."""
    response = case.call(timeout=REQUEST_TIMEOUT)
    case.validate_response(response, checks=CHECKS)
