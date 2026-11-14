"""FUZZ-05 follow-up: crafted date and duration boundaries for kytos/maintenance.

Tracker row FUZZ-05. These are the specific inputs the fuzzer in
test_e2e_151 aims at, written out so each one is a readable regression test.

Reading the NApp (main.py, models.py) suggests three ways to get an unhandled
OverflowError, which Kytos turns into a 500 that, with the default
``api_traceback_on_500 = True``, includes the full Python traceback:

* ``PATCH /v1/{id}/extend`` on a running window that was created without an
  ``end``. The model's default end is ``datetime.max``, so adding even one
  minute overflows.
* ``PATCH /v1/{id}/extend`` with a duration the OpenAPI spec allows (integer,
  minimum 0, no maximum) but ``datetime``/``timedelta`` cannot hold.
* A start or end near year 9999 with a negative UTC offset. Validation
  accepts it, but converting it to UTC for the database overflows.

The NApp handlers only catch ValueError, ValidationError, DuplicateKeyError
and OverlapError, and OverflowError is none of those.

Expected (secure) behaviour: a 4xx, never a 5xx, no traceback or file paths
in the body, and the controller and the window list keep working.

If these fail on a real Kytos, that is the finding: open an issue on
kytos-ng/maintenance and then mark the failing cases xfail with the issue
link, as done for REST-01.

Run with ``FUZZ_NO_MININET=1`` to skip Mininet: every window uses a made-up
switch with ``ignore_no_exists``.
"""
import pytest
import requests

from tests.kytos_only import KYTOS_API, make_network, settle
from tests.maintenance_helpers import (
    MW_API,
    REQUEST_TIMEOUT,
    create_pending_window,
    create_running_window,
    end_window,
    get_window,
    utc_in,
)
from tests.security_checks import find_leaks

STATUS_URL = f"{KYTOS_API}/core/status/"

# Durations the spec accepts but datetime/timedelta cannot represent.
OVERFLOW_EXTENSIONS = {
    "days_at_timedelta_max": {"days": 999999999},
    "minutes_past_c_int": {"minutes": 10**15},
    "seconds_2_pow_63": {"seconds": 2**63},
    "hours_huge": {"hours": 10**12},
}

# Timestamps the NApp's own format ("%Y-%m-%dT%H:%M:%S%z") parses and the
# start-in-the-past check accepts, but which overflow when converted to UTC.
FAR_FUTURE_NEGATIVE_OFFSET = {
    "start_9999_minus_10h": {"start": "9999-12-31T23:00:00-1000"},
    "start_9999_minus_23h59": {"start": "9999-12-31T23:59:59-2359"},
    "end_9999_minus_1h": {"start_offset_days": 1, "end": "9999-12-31T23:59:59-0100"},
}

created = []


def assert_clean_rejection(response, what, allow_success=False):
    """No 5xx, no leaked internals; 4xx unless success is acceptable."""
    body = response.text
    assert response.status_code < 500, (
        f"{what}: HTTP {response.status_code}: {body[:300]!r}")
    leaks = find_leaks(body)
    assert not leaks, f"{what}: leaked {', '.join(leaks)}: {body[:300]!r}"
    if not allow_success:
        assert 400 <= response.status_code < 500, (
            f"{what}: expected 4xx, got {response.status_code}: {body[:300]!r}")


def controller_alive():
    response = requests.get(STATUS_URL, timeout=10)
    assert response.status_code == 200, response.text
    assert response.json()["response"] == "running", response.text


@pytest.fixture(scope="module")
def net():
    network = make_network(napps=("maintenance",))
    network.start(start_controller=False)
    network.restart_kytos_clean()
    settle()
    yield network
    for mw_id in created:
        end_window(mw_id)
    network.stop()


@pytest.fixture(autouse=True)
def controller_survives(net):
    yield
    controller_alive()


@pytest.fixture(scope="module")
def running_window_1h(net):
    """A running window that ends in an hour, shared by the overflow cases."""
    mw_id = create_running_window(end=utc_in(hours=1))
    created.append(mw_id)
    return mw_id


def test_extend_window_without_end(net):
    """Extending an open-ended running window must not overflow into a 500."""
    mw_id = create_running_window(end=None)
    created.append(mw_id)
    response = requests.patch(
        f"{MW_API}/{mw_id}/extend", json={"minutes": 1}, timeout=REQUEST_TIMEOUT)
    # Either answer is reasonable: refuse (4xx) or accept and keep the end.
    assert_clean_rejection(response, "extend open-ended window", allow_success=True)
    window = get_window(mw_id)
    assert window and window["status"] == "running", window


@pytest.mark.parametrize("payload", OVERFLOW_EXTENSIONS.values(),
                         ids=OVERFLOW_EXTENSIONS.keys())
def test_extend_overflow(running_window_1h, payload):
    """Spec-valid but unrepresentable durations are rejected with a 4xx."""
    before = get_window(running_window_1h)
    response = requests.patch(
        f"{MW_API}/{running_window_1h}/extend", json=payload,
        timeout=REQUEST_TIMEOUT)
    assert_clean_rejection(response, f"extend by {payload}")
    after = get_window(running_window_1h)
    assert after and after["end"] == before["end"], (before, after)


@pytest.mark.parametrize("dates", FAR_FUTURE_NEGATIVE_OFFSET.values(),
                         ids=FAR_FUTURE_NEGATIVE_OFFSET.keys())
def test_create_far_future_negative_offset(net, dates):
    """A date that overflows when converted to UTC must not cause a 500."""
    payload = {
        "description": "far future negative offset",
        "start": dates.get("start") or utc_in(days=dates["start_offset_days"]),
        "switches": ["00:00:00:00:00:ee:ff:01"],
        "force": True,
        "ignore_no_exists": True,
    }
    if "end" in dates:
        payload["end"] = dates["end"]
    response = requests.post(MW_API, json=payload, timeout=REQUEST_TIMEOUT)
    # Storing it correctly (201) is fine too, as long as nothing breaks.
    assert_clean_rejection(response, f"create {dates}", allow_success=True)
    if response.status_code == 201:
        created.append(response.json()["mw_id"])


def test_update_pending_to_far_future_negative_offset(net):
    """Same overflow through PATCH /v1/{id} on a pending window."""
    mw_id = create_pending_window()
    created.append(mw_id)
    response = requests.patch(
        f"{MW_API}/{mw_id}", json={"end": "9999-12-31T23:59:59-0100"},
        timeout=REQUEST_TIMEOUT)
    assert_clean_rejection(response, "update end to 9999 -0100", allow_success=True)


def test_window_list_still_works(net):
    """Nothing above may leave a record that breaks listing for everyone."""
    response = requests.get(MW_API, timeout=REQUEST_TIMEOUT)
    assert response.status_code == 200, response.text[:300]
    assert isinstance(response.json(), list)
