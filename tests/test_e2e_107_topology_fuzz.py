"""FUZZ-03: Schemathesis fuzzing of the topology NApp endpoints.

Generates valid and deliberately invalid requests from the NApp's own
openapi.yml and asserts that the API never returns a 5xx and never leaks
internal details (tracebacks, file paths, library names) in a response.

The state is reset before every endpoint because several operations are
destructive (delete switch/link/interface, disable, metadata writes), and the
controller must still be running after each one.

Module-level functions and fixtures are used instead of the usual TestE2E*
class: with schemathesis 3.39.16 and pytest 8.2.0 a @schema.parametrize()
method inside a class breaks the xunit setup_method/teardown_method hooks.

Set FUZZ_NO_MININET=1 to run against Kytos alone, without Mininet / Open
vSwitch (see tests/kytos_only.py for the trade-off).
"""
import pytest

from tests.fuzz_helpers import (KYTOS_URL, assert_controller_running,
                                fuzz_settings, load_napp_schema, run_case)
from tests.kytos_only import make_network, no_mininet, settle

# topology's spec declares `servers: /api/kytos/topology`, so pass the
# complete base URL explicitly
schema = load_napp_schema("topology",
                          base_url=f"{KYTOS_URL}/api/kytos/topology")


@pytest.fixture(scope="module")
def net():
    # FUZZ_NO_MININET=1 runs against Kytos alone (empty topology)
    network = make_network()
    network.start(start_controller=False)
    if no_mininet():
        # nothing to destroy without switches, so one clean start is enough
        network.restart_kytos_clean()
    yield network
    network.stop()


@pytest.fixture(autouse=True)
def clean_state_and_survival(net):
    if not no_mininet():
        # clean database, every switch/interface/link enabled
        net.restart_kytos_clean()
        settle()
    yield
    assert_controller_running()


@schema.parametrize()
@fuzz_settings()
def test_fuzz_topology(case):
    run_case(case)
