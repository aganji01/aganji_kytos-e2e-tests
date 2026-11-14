"""Helpers for the maintenance security tests (FUZZ-05).

Windows are created on made-up switch IDs with ``ignore_no_exists`` so the
tests run the same with Mininet or with FUZZ_NO_MININET=1, and never put a
real switch into maintenance. ``force`` limits overlap checks to components,
and every window gets its own made-up switch, so test windows never block
each other.
"""
import itertools
import time
from datetime import datetime, timedelta, timezone

import requests

CONTROLLER = "127.0.0.1"
MW_API = f"http://{CONTROLLER}:8181/api/kytos/maintenance/v1"
TIME_FMT = "%Y-%m-%dT%H:%M:%S+0000"
REQUEST_TIMEOUT = 15

_switch_numbers = itertools.count(1)


def fake_switch():
    """A dpid that no Mininet topology in this repo uses (ee in byte 6)."""
    number = next(_switch_numbers)
    return f"00:00:00:00:00:ee:{(number >> 8) & 0xff:02x}:{number & 0xff:02x}"


def utc_in(**delta):
    """A TIME_FMT timestamp ``delta`` from now."""
    return (datetime.now(timezone.utc) + timedelta(**delta)).strftime(TIME_FMT)


def create_window(start, end=None, **extra):
    """Create a window on a fresh made-up switch and return its id."""
    payload = {
        "description": "security test window",
        "start": start,
        "switches": [fake_switch()],
        "force": True,
        "ignore_no_exists": True,
        **extra,
    }
    if end is not None:
        payload["end"] = end
    response = requests.post(MW_API, json=payload, timeout=REQUEST_TIMEOUT)
    assert response.status_code == 201, response.text
    return response.json()["mw_id"]


def get_window(mw_id):
    """Return the window as JSON, or None if it does not exist."""
    response = requests.get(f"{MW_API}/{mw_id}", timeout=REQUEST_TIMEOUT)
    if response.status_code == 404:
        return None
    assert response.status_code == 200, response.text
    return response.json()


def wait_status(mw_id, status, timeout=30):
    """Wait until the window reaches ``status``; return the window."""
    deadline = time.monotonic() + timeout
    window = None
    while time.monotonic() < deadline:
        window = get_window(mw_id)
        if window and window.get("status") == status:
            return window
        time.sleep(0.5)
    raise AssertionError(f"window {mw_id} not {status} after {timeout}s: {window}")


def create_running_window(end=None, start_delay=3):
    """Create a window that starts in a few seconds and wait until it runs.

    The API refuses a start in the past, so a running window has to be
    created slightly in the future. Without ``end`` the NApp stores its
    default end, the largest datetime Python supports.
    """
    mw_id = create_window(utc_in(seconds=start_delay), end)
    wait_status(mw_id, "running", timeout=start_delay + 30)
    return mw_id


def create_pending_window():
    """Create a window far enough in the future to stay pending."""
    return create_window(utc_in(days=3650), utc_in(days=3651))


def end_window(mw_id):
    """Best-effort cleanup: finish a running window, delete a pending one."""
    try:
        window = get_window(mw_id)
    except AssertionError:
        return
    if not window:
        return
    if window.get("status") == "running":
        requests.patch(f"{MW_API}/{mw_id}/end", timeout=REQUEST_TIMEOUT)
    elif window.get("status") == "pending":
        requests.delete(f"{MW_API}/{mw_id}", timeout=REQUEST_TIMEOUT)
