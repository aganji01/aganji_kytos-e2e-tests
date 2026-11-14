"""REST-07: malformed dpid / interface_id values on topology endpoints.

Crafted identifiers (extra colons, overflowing or non-hex fields, path
tricks, control characters, oversized strings) are sent to topology
endpoints that take a dpid or an interface_id. Expected: a clean 4xx. Not a
5xx, not a 2xx (a malformed ID must never be accepted as a real element)
and no internal details in the body. Only read, enable and disable
endpoints are used, and a malformed ID must never match a real element, so
the topology is not modified.

Numbering follows the agreed 1xx scheme: topology tests live in the 10x band
(the existing 05, 06 and 08 will become 105, 106 and 108), so 109 is free.

Set FUZZ_NO_MININET=1 to run against Kytos alone, without Mininet / Open
vSwitch (see tests/kytos_only.py). The topology is then empty, so every
well-formed-but-unknown ID also gets a 404.
"""
from urllib.parse import quote

import pytest
import requests

from tests.kytos_only import CONTROLLER, make_network, settle

TOPOLOGY_API = f"http://{CONTROLLER}:8181/api/kytos/topology/v3"
STATUS_URL = f"http://{CONTROLLER}:8181/api/kytos/core/status/"

# Plain-substring leak signs (a subset of tests/security_checks.py), so a
# failure message names the exact text that leaked.
LEAK_MARKERS = (
    "Traceback (most recent call last)",
    "site-packages",
    "/var/lib/kytos",
    'File "',
    "pymongo",
    "starlette",
    "openapi_core",
)

VALID_DPID = "00:00:00:00:00:00:00:01"

MALFORMED_DPIDS = {
    "trailing_colon": VALID_DPID + ":",
    "extra_octet": VALID_DPID + ":01",
    "too_short": "00:00:00:01",
    "overflow_72bit": "ff:ff:ff:ff:ff:ff:ff:ff:ff",
    "non_hex_letter": "00:00:00:00:00:00:00:0g",
    "non_hex_word": "zz:zz:zz:zz:zz:zz:zz:zz",
    "no_separators": "0000000000000001",
    "double_colon": "00:00:00:00::00:00:01",
    "leading_space": " " + VALID_DPID,
    "negative": "-1",
    "hex_prefix": "0x0000000000000001",
    # Arabic-Indic digits, written as escapes
    "unicode_digits": ":".join(["\u0660\u0660"] * 7 + ["\u0660\u0661"]),
    "rtl_override": "\u202e" + VALID_DPID,  # right-to-left override
    "nul_byte": VALID_DPID + "\x00",
    "newline": VALID_DPID + "\nX-Injected: 1",
    "traversal": "../../etc/passwd",
    "nosql_operator": '{"$ne": null}',
    "oversized": "0" * 10000,
}

MALFORMED_PORTS = {
    "empty_port": VALID_DPID + ":",
    "overflow_32bit": VALID_DPID + ":4294967296",
    "huge_number": VALID_DPID + ":99999999999999999999999",
    "negative_port": VALID_DPID + ":-1",
    "non_numeric_port": VALID_DPID + ":abc",
    "extra_field": VALID_DPID + ":1:2",
    "port_only": ":1",
    "float_port": VALID_DPID + ":1.5",
    "hex_port": VALID_DPID + ":0x1",
    "nul_in_port": VALID_DPID + ":1\x00",
}

# (method, endpoint template). All use a single path parameter.
DPID_ENDPOINTS = [
    ("GET", "/switches/{}/metadata"),
    ("POST", "/switches/{}/enable"),
    ("POST", "/switches/{}/disable"),
    ("POST", "/interfaces/switch/{}/enable"),
    ("POST", "/interfaces/switch/{}/disable"),
]
INTERFACE_ENDPOINTS = [
    ("GET", "/interfaces/{}/metadata"),
    ("POST", "/interfaces/{}/enable"),
    ("POST", "/interfaces/{}/disable"),
    ("GET", "/interfaces/{}/tag_ranges"),
]


def _cases(endpoints, values):
    return [
        pytest.param(method, template, value, id=f"{method}{template}-{name}")
        for method, template in endpoints
        for name, value in values.items()
    ]


class TestE2ETopologyMalformedIds:
    net = None

    @classmethod
    def setup_class(cls):
        # FUZZ_NO_MININET=1 runs against Kytos alone (empty topology)
        cls.net = make_network()
        cls.net.start(start_controller=False)
        cls.net.restart_kytos_clean()
        settle()

    @classmethod
    def teardown_class(cls):
        cls.net.stop()

    def _send(self, method, template, value):
        url = TOPOLOGY_API + template.format(quote(value, safe=""))
        # Do not follow redirects: a 3xx would hide the original answer.
        response = requests.request(
            method, url, json={} if method == "POST" else None,
            allow_redirects=False, timeout=15)
        assert response.status_code < 500, (
            f"{method} {url[:120]} -> {response.status_code}: "
            f"{response.text[:300]}")
        assert not 200 <= response.status_code < 300, (
            f"malformed id accepted: {method} {url[:120]} -> "
            f"{response.status_code}: {response.text[:300]}")
        for marker in LEAK_MARKERS:
            assert marker not in response.text, (
                f"{method} {url[:120]} leaked {marker!r}: "
                f"{response.text[:300]}")
        return response

    def _controller_alive(self):
        response = requests.get(STATUS_URL, timeout=10)
        assert response.status_code == 200, response.text
        assert response.json()["response"] == "running", response.text

    @pytest.mark.parametrize(
        "method,template,value", _cases(DPID_ENDPOINTS, MALFORMED_DPIDS))
    def test_malformed_dpid(self, method, template, value):
        """REST-07: malformed dpid is rejected cleanly."""
        self._send(method, template, value)
        self._controller_alive()

    @pytest.mark.parametrize(
        "method,template,value",
        _cases(INTERFACE_ENDPOINTS, MALFORMED_PORTS))
    def test_malformed_interface_id(self, method, template, value):
        """REST-07: malformed interface_id is rejected cleanly."""
        self._send(method, template, value)
        self._controller_alive()
