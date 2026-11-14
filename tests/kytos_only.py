"""Run the security tests against Kytos alone, without Mininet / Open vSwitch.

Set ``FUZZ_NO_MININET=1`` to use this instead of ``tests.helpers.NetworkTest``.
It starts and stops ``kytosd`` the same way ``NetworkTest.start_controller``
does, but creates no virtual switches. That makes the fuzz and malformed-input
tests runnable where Open vSwitch is unavailable (for example Docker Desktop
on macOS).

Trade-off: with no switches the topology is empty, so many endpoints answer
404 before reaching their deeper logic. The tests still catch 5xx errors,
leaked internals and crashes on hostile input, but they exercise less of each
NApp than a run with Mininet.

This module deliberately imports nothing from ``tests.helpers`` (which imports
Mininet at load time) and nothing from schemathesis.
"""
import os
import time

import requests

CONTROLLER = "127.0.0.1"
KYTOS_API = f"http://{CONTROLLER}:8181/api/kytos"
STATUS_URL = f"{KYTOS_API}/core/status/"
BASE_ENV = os.environ.get("VIRTUAL_ENV", None) or "/"

# How to tell that a NApp has finished loading: (method, path under KYTOS_API,
# check on the status code). A 404 means the route is not registered yet.
NAPP_PROBES = {
    "topology": ("GET", "/topology/v3/", lambda code: code == 200),
    "pathfinder": ("POST", "/pathfinder/v3/", lambda code: code != 404),
    "maintenance": ("GET", "/maintenance/v1", lambda code: code == 200),
}
DEFAULT_NAPPS = ("topology", "pathfinder")


def no_mininet():
    """True when the tests should run without Mininet."""
    return os.environ.get("FUZZ_NO_MININET", "").lower() in ("1", "true", "yes")


def settle(seconds=10):
    """Give Kytos time to run LLDP and link discovery. Needless without switches."""
    if not no_mininet():
        time.sleep(seconds)


class KytosOnly:
    """Controller lifecycle with the same method names the tests use on NetworkTest."""

    def __init__(self, napps=DEFAULT_NAPPS):
        self.napps = tuple(napps)

    def start(self, start_controller=True):
        if start_controller:
            self.start_controller(clean_config=True)

    def drop_database(self):
        """Drop the Kytos database, as NetworkTest.drop_database does."""
        host_seeds = os.environ.get("MONGO_HOST_SEEDS")
        db_name = os.environ.get("MONGO_DBNAME")
        if not host_seeds or not db_name:
            print("MONGO_HOST_SEEDS / MONGO_DBNAME not set: database not dropped")
            return
        from pymongo import MongoClient
        from pymongo.errors import ServerSelectionTimeoutError

        client = MongoClient(
            host_seeds.split(","),
            username=os.environ.get("MONGO_USERNAME"),
            password=os.environ.get("MONGO_PASSWORD"),
            connect=False,
            authsource=db_name,
            readpreference="primaryPreferred",
        )
        try:
            client.drop_database(db_name)
        except ServerSelectionTimeoutError as exc:
            print(f"FAIL to drop database. {exc}")

    def stop_kytosd(self):
        """Stop kytosd, forcing it if it does not exit within 5 seconds."""
        pid_path = os.path.join(BASE_ENV, "var/run/kytos/kytosd.pid")
        os.system("pkill kytosd")
        time.sleep(5)
        if os.path.exists(pid_path):
            print("kytosd pid file still exists after 5 seconds. Force stop!")
            os.system("pkill -9 kytosd")
            os.system(f"rm -f {pid_path}")

    def start_controller(self, clean_config=False, enable_all=False,
                         database="mongodb", port=None,
                         extra_args=os.environ.get("KYTOSD_EXTRA_ARGS", ""),
                         **_ignored):
        """Same arguments as NetworkTest.start_controller; Mininet-only ones are ignored."""
        self.stop_kytosd()
        if clean_config and database:
            self.drop_database()
        daemon = "kytosd"
        if database:
            daemon += f" --database {database}"
        if port:
            daemon += f" --port {port}"
        if enable_all:
            daemon += " -E"
        if extra_args:
            daemon += " " + extra_args
        os.system(daemon)
        self.wait_controller_start()

    def wait_controller_start(self, timeout=60):
        """Wait until core/status reports running."""
        waited = 0
        last_error = ""
        while waited < timeout:
            try:
                response = requests.get(STATUS_URL, timeout=3)
                assert response.json()["response"] == "running", response.text
                return
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                time.sleep(0.5)
                waited += 0.5
        raise RuntimeError(
            f"Timeout while starting Kytos. Last error: {last_error}")

    def wait_napps_loaded(self, timeout=90):
        """Wait until every NApp in self.napps answers its probe route."""
        waited = 0
        last = ""
        while waited < timeout:
            try:
                states = {}
                for napp in self.napps:
                    method, path, ready = NAPP_PROBES[napp]
                    kwargs = {"json": {}} if method == "POST" else {}
                    response = requests.request(
                        method, f"{KYTOS_API}{path}", timeout=3, **kwargs)
                    states[napp] = (response.status_code, ready(response.status_code))
                last = ", ".join(f"{n}={code}" for n, (code, _) in states.items())
                if all(ok for _, ok in states.values()):
                    return
            except Exception as exc:  # noqa: BLE001
                last = str(exc)
            time.sleep(1)
            waited += 1
        raise RuntimeError(f"NApps not loaded after {timeout}s ({last})")

    def restart_kytos_clean(self):
        """Clean database, restart Kytos, wait until the NApps are serving."""
        self.start_controller(clean_config=True, enable_all=True)
        self.wait_napps_loaded()

    def wait_switches_connect(self):
        """No switches exist in this mode."""

    def stop(self):
        """Like NetworkTest.stop, leave kytosd running (useful for debugging)."""


def make_network(topo_name=None, napps=DEFAULT_NAPPS):
    """NetworkTest normally, or KytosOnly when FUZZ_NO_MININET is set.

    ``napps`` only matters without Mininet: the NApps whose routes must answer
    before the tests start.
    """
    if no_mininet():
        return KytosOnly(napps=napps)
    from tests.helpers import NetworkTest

    if topo_name:
        return NetworkTest(CONTROLLER, topo_name=topo_name)
    return NetworkTest(CONTROLLER)
