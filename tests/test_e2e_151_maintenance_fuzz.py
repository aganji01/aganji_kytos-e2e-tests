"""FUZZ-05: Schemathesis fuzzing of the kytos/maintenance REST API.

Tracker row FUZZ-05. Every endpoint in the NApp's own openapi.yml gets valid
and invalid inputs. Each response must not be a 5xx and must not leak
internals (tracebacks, file paths, library names), and the controller must
still be running afterwards.

Most maintenance routes take a ``{mw_id}``. A random id only reaches the
"not found" branch, so every generated request that has one is also sent
against two seeded windows: one pending and one running. That way the
update, delete, end and extend handlers run their real logic on hostile
input. Seeds are replaced whenever a request deletes or changes them, so
every request starts from the same state: a pending window ten years out
and a running window that ends two hours from now. The running seed is not
used for ``/end``, which would finish it (test_e2e_50 already covers ending
a running window).

A failure on a seeded id prints a curl line whose id existed only during
that run. To replay it, create a window in the same state (see
maintenance_helpers) and send the same body to its id.

Only ``PATCH /v1/{mw_id}/extend`` validates against the spec
(@validate_openapi). The other handlers parse the body themselves with
pydantic, so the spec is a guide here, not what the server enforces.

Known gap: the spec forbids ``force`` and ``ignore_no_exists`` on create
(allOf with additionalProperties: false), so generated creates never set
them, and creates on random switch ids stop at the item-existence check.
test_e2e_152 covers the date and duration boundaries explicitly.

Run with ``FUZZ_NO_MININET=1`` to skip Mininet: seeds use made-up switches
with ``ignore_no_exists``.
"""
import pytest

from tests.fuzz_helpers import (
    KYTOS_URL,
    assert_controller_running,
    fuzz_settings,
    load_napp_schema,
    run_case,
)
from tests.kytos_only import make_network, settle
from tests.maintenance_helpers import (
    create_pending_window,
    create_running_window,
    end_window,
    get_window,
    utc_in,
)

schema = load_napp_schema(
    "maintenance", base_url=f"{KYTOS_URL}/api/kytos/maintenance")


# Fields that must be unchanged for a seed to be reused. If an earlier request
# changed any of them (for example a successful extend moved the end), the
# seed is replaced, so every request sees the same starting state and a
# failure's reproducer does not depend on what ran before it.
SEED_FIELDS = ("id", "status", "start", "end", "switches", "interfaces",
               "links", "description")


def _snapshot(window):
    return {key: window.get(key) for key in SEED_FIELDS} if window else None


class Seeds:
    """One pending and one running window in a known state."""

    def __init__(self):
        self.pending = None   # (mw_id, snapshot)
        self.running = None
        self.all_ids = []

    @staticmethod
    def _unchanged(seed):
        if seed is None:
            return False
        mw_id, snapshot = seed
        return _snapshot(get_window(mw_id)) == snapshot

    def _replace(self, seed, create):
        if seed is not None:
            end_window(seed[0])
        mw_id = create()
        self.all_ids.append(mw_id)
        return mw_id, _snapshot(get_window(mw_id))

    def ensure(self):
        if not self._unchanged(self.pending):
            self.pending = self._replace(self.pending, create_pending_window)
        if not self._unchanged(self.running):
            self.running = self._replace(
                self.running,
                lambda: create_running_window(end=utc_in(hours=2), start_delay=2))

    def ids_for(self, case):
        """Seed ids to substitute for this case's mw_id."""
        self.ensure()
        ids = [self.pending[0]]
        if not case.path.endswith("/end"):
            ids.append(self.running[0])
        return ids

    def cleanup(self):
        for mw_id in self.all_ids:
            end_window(mw_id)


SEEDS = Seeds()


@pytest.fixture(scope="module")
def net():
    network = make_network(napps=("maintenance",))
    network.start(start_controller=False)
    network.restart_kytos_clean()
    settle()
    yield network
    SEEDS.cleanup()
    network.stop()


@pytest.fixture(autouse=True)
def controller_survives(net):
    yield
    assert_controller_running()


@schema.parametrize()
@fuzz_settings()
def test_fuzz_maintenance(case):
    run_case(case)
    if "mw_id" not in (case.path_parameters or {}):
        return
    for seed_id in SEEDS.ids_for(case):
        variant = case.partial_deepcopy()
        variant.path_parameters = {**case.path_parameters, "mw_id": seed_id}
        run_case(variant)
