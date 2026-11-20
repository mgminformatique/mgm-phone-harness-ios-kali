"""USB framing, XCTest actions and stop semantics using a local fake usbmuxd."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import plistlib
import socket
from pathlib import Path
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "phone-harness"))
import cli
import usbios


UDID = "00008140-001234567890ABCD"
OTHER = "00008140-001234567890ABCE"
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aV1sAAAAASUVORK5CYII="
SOURCE = """<App>
  <Button visible="true" label="Wi-Fi" x="20" y="20" width="40" height="40"/>
  <XCUIElementTypeSecureTextField visible="true" label="Secret" x="5" y="5" width="20" height="20"/>
</App>"""


class UsbFixture(socketserver.StreamRequestHandler):
    def plist(self):
        header = self.rfile.read(usbios.HEADER.size)
        if not header:
            return None, None
        length, _, _, tag = usbios.HEADER.unpack(header)
        return plistlib.loads(self.rfile.read(length - usbios.HEADER.size)), tag

    def reply(self, body, tag):
        data = plistlib.dumps(body)
        self.wfile.write(usbios.HEADER.pack(usbios.HEADER.size + len(data), 1, 8, tag) + data)

    def handle(self):
        command, tag = self.plist()
        if command["MessageType"] != "ListDevices":
            return
        devices = [
            {"DeviceID": number, "Properties": {"SerialNumber": serial, "ConnectionType": kind}}
            for number, serial, kind in [(9, OTHER, "USB"), (4, UDID, "Network"), (3, UDID, "USB")]
        ]
        self.reply({"DeviceList": devices}, tag)
        request, tag = self.plist()
        if request is None:
            return
        if request["DeviceID"] != 3 or request["PortNumber"] != socket.htons(8100):
            self.reply({"MessageType": "Result", "Number": 2}, tag)
            return
        self.reply({"MessageType": "Result", "Number": 0 if self.server.driver else 3}, tag)
        if not self.server.driver:
            return
        method, path, _ = self.rfile.readline().decode().split()
        headers = {}
        while (row := self.rfile.readline()) not in (b"\r\n", b""):
            field, value = row.decode().split(":", 1)
            headers[field.lower()] = value.strip()
        if method == "POST":
            payload = json.loads(self.rfile.read(int(headers["content-length"])))
            self.server.posts.append((path, payload))
            if path == "/session":
                self.server.session = "fixture-session"
                if self.server.rotate_on_session:
                    self.server.size = {"width": 100, "height": 200}
            if self.server.drop_gesture and path.endswith("/wda/tap"):
                return
        body = json.dumps({"value": {
            "/status": {"ready": True},
            "/wda/locked": self.server.locked,
            "/wda/activeAppInfo": {"bundleId": "com.apple.Preferences"},
            "/window/size": self.server.size,
            "/screenshot": PNG,
            "/source?format=xml": SOURCE,
        }.get(path), "sessionId": self.server.session}).encode()
        self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


@unittest.skipUnless(sys.platform == "linux", "Unix usbmuxd on Linux")
class KaliIphoneTests(unittest.TestCase):
    def setUp(self):
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        self.workspace = Path(workspace.name)
        self.image = self.workspace / "screen.png"
        wire = str(self.workspace / "mux")
        self.server = socketserver.ThreadingUnixStreamServer(wire, UsbFixture)
        self.server.driver = True
        self.server.session = None
        self.server.locked = False
        self.server.posts = []
        self.server.drop_gesture = False
        self.server.rotate_on_session = False
        self.server.size = {"width": 100, "height": 100}
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        socket_path = patch.object(usbios, "USBMUX_SOCKET", wire)
        socket_path.start()
        self.addCleanup(socket_path.stop)

    def execute(self, *args, udid=UDID, terminal=False, reply="oui"):
        output, errors = io.StringIO(), io.StringIO()
        terminal_input = io.StringIO(reply + "\n")
        terminal_input.isatty = errors.isatty = lambda: terminal
        with redirect_stdout(output), redirect_stderr(errors), patch.object(sys, "stdin", terminal_input):
            code = cli.main([*args, "--device", udid])
        return code, json.loads(output.getvalue())

    def tap(self, **kwargs):
        return self.execute("tap", ".4", ".4", "--reference", str(self.image), **kwargs)

    def test_usb_capture_and_tree_without_mutation(self):
        self.assertEqual(self.execute("status"), (0, {"state": "ready"}))
        code, result = self.execute("capture", str(self.image))
        self.assertEqual(code, 0)
        self.assertEqual(result["screen"]["pixels"], [1, 1])
        self.assertEqual(self.image.read_bytes(), base64.b64decode(PNG))
        self.assertEqual(self.image.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.execute("capture", str(self.image)), (1, {"state": "output-exists"}))
        code, result = self.execute("read")
        self.assertEqual(code, 0)
        self.assertEqual(result["text"], [{"text": "Wi-Fi", "source": "tree", "confidence": None, "x": .4, "y": .4}])
        self.assertEqual(self.server.posts, [])

    def test_wrong_target_unavailable_driver_and_locked_phone(self):
        self.assertEqual(self.execute("status", udid=OTHER), (1, {"state": "missing"}))
        self.server.driver = False
        self.assertEqual(self.execute("status"), (1, {"state": "driver-required"}))
        self.server.driver = True
        self.server.locked = True
        self.assertEqual(self.execute("capture", str(self.image)), (1, {"state": "locked"}))
        self.assertFalse(self.image.exists())
        self.assertEqual(self.server.posts, [])

    def test_tap_requires_live_confirmation_and_matching_capture(self):
        self.assertEqual(self.tap(), (1, {"state": "terminal-required"}))
        self.image.write_bytes(b"wrong image")
        self.assertEqual(self.tap(terminal=True), (1, {"state": "stale"}))
        self.image.write_bytes(base64.b64decode(PNG))
        self.assertEqual(self.tap(terminal=True, reply="n"), (1, {"state": "cancelled"}))
        self.assertEqual(self.server.posts, [])
        self.assertEqual(self.tap(terminal=True), (0, {"state": "ok", "action": "tap"}))
        self.assertEqual([route for route, _ in self.server.posts], ["/session", "/session/fixture-session/wda/tap"])
        self.assertEqual(self.server.posts[-1][1], {"x": 40, "y": 40})

    def test_geometry_change_blocks_the_tap(self):
        self.image.write_bytes(base64.b64decode(PNG))
        self.server.rotate_on_session = True
        self.assertEqual(self.tap(terminal=True), (1, {"state": "stale"}))
        self.assertEqual([route for route, _ in self.server.posts], ["/session"])

    def test_lost_response_is_not_replayed(self):
        self.image.write_bytes(base64.b64decode(PNG))
        self.server.drop_gesture = True
        self.assertEqual(self.tap(terminal=True), (1, {"state": "unconfirmed"}))
        self.assertEqual([route for route, _ in self.server.posts], ["/session", "/session/fixture-session/wda/tap"])
