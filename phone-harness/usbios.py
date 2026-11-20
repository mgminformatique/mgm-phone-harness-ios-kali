"""iPhone over the local usbmuxd socket and an operator-started XCTest driver."""
from __future__ import annotations

import base64
import binascii
import http.client
import json
import plistlib
import re
import socket
import struct
import xml.etree.ElementTree as ET

from actions import Blocked, number


USBMUX_SOCKET = "/var/run/usbmuxd"
HEADER = struct.Struct("<IIII")
WDA_PORT = 8100
MAX_REPLY = 7_000_000
UDID = re.compile(r"[A-Fa-f0-9-]{16,64}")
BUNDLE_ID = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+){1,12}")


def read_exact(conn, length):
    result = bytearray()
    while len(result) < length:
        chunk = conn.recv(length - len(result))
        if not chunk:
            raise Blocked("transport")
        result.extend(chunk)
    return bytes(result)


def usbmux(conn, message, tag):
    payload = plistlib.dumps({"ClientVersionString": "MGM Phone", "ProgName": "MGM Phone", **message})
    conn.sendall(HEADER.pack(HEADER.size + len(payload), 1, 8, tag) + payload)
    length, version, protocol, reply_tag = HEADER.unpack(read_exact(conn, HEADER.size))
    if not HEADER.size < length <= 1_000_000 or (version, protocol, reply_tag) != (1, 8, tag):
        raise Blocked("transport")
    response = plistlib.loads(read_exact(conn, length - HEADER.size))
    if not isinstance(response, dict):
        raise Blocked("transport")
    return response


def device_id(conn, udid):
    response = usbmux(conn, {"MessageType": "ListDevices"}, 1)
    rows = response.get("DeviceList")
    if not isinstance(rows, list):
        raise Blocked("transport")
    matches = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("Properties"), dict):
            raise Blocked("transport")
        props = row["Properties"]
        serial = props.get("SerialNumber")
        if props.get("ConnectionType") == "USB" and isinstance(serial, str) and serial.casefold() == udid.casefold():
            if type(row.get("DeviceID")) is not int:
                raise Blocked("identity-unverified")
            matches.append(row["DeviceID"])
    if len(matches) != 1:
        raise Blocked("missing" if not matches else "identity-unverified")
    return matches[0]


def wda_request(udid, method, path, payload=None, timeout=3):
    # Resolve the same physical USB device on every request. HTTP is never
    # exposed on the host, and proxy settings or redirects never come into play.
    submitted = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(timeout)
            conn.connect(USBMUX_SOCKET)
            target = device_id(conn, udid)
            response = usbmux(conn, {"MessageType": "Connect", "DeviceID": target,
                                     "PortNumber": socket.htons(WDA_PORT)}, 2)
            if response.get("MessageType") != "Result":
                raise Blocked("transport")
            failure = response.get("Number")
            if failure != 0:
                raise Blocked({2: "missing", 3: "driver-required"}.get(failure, "transport"))
            client = http.client.HTTPConnection("localhost", WDA_PORT, timeout=timeout)
            client.sock = conn
            body = None if payload is None else json.dumps(payload).encode()
            submitted = method == "POST"
            client.request(method, path, body=body, headers={"Content-Type": "application/json", "Connection": "close"})
            with client.getresponse() as reply:
                if reply.status == 404 and method == "GET":
                    raise Blocked("unsupported")
                if reply.status != 200:
                    raise Blocked("transport")
                data = reply.read(MAX_REPLY + 1)
    except Blocked as exc:
        if submitted:
            raise Blocked("unconfirmed") from exc
        raise
    except (FileNotFoundError, ConnectionRefusedError) as exc:
        raise Blocked("no-usbmuxd") from exc
    except PermissionError as exc:
        raise Blocked("usb-permission") from exc
    except (OSError, http.client.HTTPException, plistlib.InvalidFileException, TypeError, ValueError) as exc:
        raise Blocked("unconfirmed" if submitted else "transport") from exc
    invalid_reply = "unconfirmed" if submitted else "transport"
    if len(data) > MAX_REPLY:
        raise Blocked(invalid_reply)
    try:
        data = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise Blocked(invalid_reply) from exc
    if not isinstance(data, dict) or "value" not in data or data.get("status", 0) != 0:
        raise Blocked(invalid_reply)
    value = data["value"]
    if isinstance(value, dict) and "error" in value:
        raise Blocked(invalid_reply)
    return data


def screen_png(value):
    try:
        result = base64.b64decode(value, validate=True)
    except (binascii.Error, TypeError, ValueError) as exc:
        raise Blocked("transport") from exc
    if len(result) < 33 or result[:8] != b"\x89PNG\r\n\x1a\n" or result[12:16] != b"IHDR":
        raise Blocked("unsupported")
    return result, *struct.unpack(">II", result[16:24])


class UsbIPhone:
    def __init__(self, udid):
        self.udid = udid
        self.session_id = None

    def request(self, method, path, payload=None):
        return wda_request(self.udid, method, path, payload, timeout=8 if method == "POST" else 3)

    def get(self, path):
        return self.request("GET", path)["value"]

    def require_unlocked(self):
        locked = self.get("/wda/locked")
        if locked is not False:
            raise Blocked("locked" if locked is True else "transport")

    def state(self):
        try:
            reply = self.request("GET", "/status")
        except Blocked as exc:
            if exc.code == "unsupported":
                raise Blocked("driver-required") from exc
            raise
        if not isinstance(reply["value"], dict) or reply["value"].get("ready") is not True:
            raise Blocked("driver-required")
        self.require_unlocked()
        self.session_id = reply.get("sessionId")
        return "ready"

    def bounds(self):
        bounds = self.get("/window/size")
        if not isinstance(bounds, dict):
            raise Blocked("transport")
        width, height = bounds.get("width"), bounds.get("height")
        if not number(width, 1, 8192) or not number(height, 1, 8192):
            raise Blocked("transport")
        return width, height

    def app_id(self):
        app = self.get("/wda/activeAppInfo")
        if not isinstance(app, dict) or not BUNDLE_ID.fullmatch(str(app.get("bundleId", ""))):
            raise Blocked("identity-unverified")
        return app["bundleId"]

    def capture(self):
        self.require_unlocked()
        app = self.app_id()
        width, height = self.bounds()
        png, px, py = screen_png(self.get("/screenshot"))
        if (not number(px, 1, 8192) or not number(py, 1, 8192)
                or abs((px / py) / (width / height) - 1) > .02):
            raise Blocked("stale")
        if (width, height) != self.bounds() or self.app_id() != app:
            raise Blocked("stale")
        return png, {"app": app, "width": width, "height": height, "pixels": [px, py]}

    def text(self):
        self.require_unlocked()
        source = self.get("/source?format=xml")
        if not isinstance(source, str) or "<!DOCTYPE" in source.upper() or "<!ENTITY" in source.upper():
            raise Blocked("transport")
        seen = set()
        result = []
        try:
            root = ET.fromstring(source)
        except ET.ParseError as exc:
            raise Blocked("transport") from exc
        for node in root.iter():
            attrs = node.attrib
            if attrs.get("visible") != "true" or node.tag == "XCUIElementTypeSecureTextField":
                continue
            label = (attrs.get("label") or attrs.get("name") or "").strip()[:200]
            if not label or not all(k in attrs for k in ("x", "y", "width", "height")):
                continue
            try:
                x, y, w, h = (float(attrs[k]) for k in ("x", "y", "width", "height"))
            except ValueError:
                continue
            token = (label, x + w / 2, y + h / 2)
            if token in seen or not number(w, 1, 8192) or not number(h, 1, 8192):
                continue
            seen.add(token)
            result.append({"text": label, "x": token[1], "y": token[2],
                           "source": "tree", "confidence": None})
            if len(result) >= 160:
                break
        return result

    def prepare_action(self, action):
        if action == "home" or self.session_id:
            return False
        # The worker observes the screen again after creating this session,
        # before it sends the authorized gesture.
        self.require_unlocked()
        started = self.request("POST", "/session", {"capabilities": {"alwaysMatch": {}, "firstMatch": [{}]}})
        value = started["value"]
        self.session_id = started.get("sessionId") or (value.get("sessionId") if isinstance(value, dict) else None)
        if not isinstance(self.session_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", self.session_id):
            raise Blocked("transport")
        return True

    def mutate(self, path, payload, *, session=True):
        self.require_unlocked()
        if session:
            if not isinstance(self.session_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,80}", self.session_id):
                raise Blocked("transport")
            path = "/session/" + self.session_id + path
        return self.request("POST", path, payload)

    def tap(self, x, y):
        return self.mutate("/wda/tap", {"x": x, "y": y})

    def press(self, x, y, duration):
        return self.mutate("/wda/touchAndHold", {"x": x, "y": y, "duration": duration})

    def drag(self, x1, y1, x2, y2):
        return self.mutate("/wda/dragfromtoforduration",
                           {"fromX": x1, "fromY": y1, "toX": x2, "toY": y2, "duration": .55})

    def scroll(self, x, y, dy):
        _, height = self.bounds()
        return self.drag(x, y, x, max(0, min(height - 1, y - dy)))

    def type_text(self, s):
        return self.mutate("/wda/keys", {"value": list(s)})

    def home(self):
        return self.mutate("/wda/homescreen", {}, session=False)

    def launch(self, name):
        known = {"settings": "com.apple.Preferences", "réglages": "com.apple.Preferences"}
        bundle = known.get(name.casefold(), name)
        if not isinstance(bundle, str) or not BUNDLE_ID.fullmatch(bundle):
            raise Blocked("unsupported")
        return self.mutate("/wda/apps/launch", {"bundleId": bundle})
