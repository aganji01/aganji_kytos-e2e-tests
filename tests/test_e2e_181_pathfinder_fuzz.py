"""FUZZ-07: Schemathesis fuzzing of pathfinder POST /api/kytos/pathfinder/v3/.

Generates valid and deliberately invalid requests from the NApp's own
openapi.yml and asserts that the API never returns a 5xx and never leaks
internal details (tracebacks, file paths, library names) in a response.
Afterwards the controller must still be running.

Written with module-level functions and fixtures instead of the usual
TestE2E* class: with schemathesis 3.39.16 and pytest 8.2.0 a
@schema.parametrize() method inside a class breaks the xunit
setup_method/teardown_method hooks (the instance is None at teardown).

Set FUZZ_NO_MININET=1 to run against Kytos alone, without Mininet / Open
vSwitch (see tests/kytos_only.py for the trade-off).
"""
import pytest

from tests.fuzz_helpers import (assert_controller_running, fuzz_settings,
                                load_napp_schema, run_case)
from tests.kytos_only import make_network, settle

# pathfinder's spec already includes the /api/kytos prefix in its paths
schema = load_napp_schema("pathfinder")


@pytest.fixture(scope="module")
def net():
    # FUZZ_NO_MININET=1 runs against Kytos alone (empty topology)
    network = make_network(topo_name="multi")
    network.start(start_controller=False)
    # clean database, every switch/interface/link enabled
    network.restart_kytos_clean()
    settle()
    yield network
    network.stop()


@pytest.fixture(autouse=True)
def controller_survives(net):
    yield
    assert_controller_running()


@schema.parametrize()
@fuzz_settings()
def test_fuzz_pathfinder(case):
    run_case(case)
