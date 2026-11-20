"""Phone Harness iOS sur un iPhone de test connecté en USB à Kali."""
import argparse
import getpass
import json
import os
from pathlib import Path
import sys
import tempfile

from actions import Blocked, number
from usbios import UDID, UsbIPhone


def udid(value):
    if not UDID.fullmatch(value) or not any(char.isalnum() for char in value):
        raise argparse.ArgumentTypeError("UDID iPhone invalide")
    return value


def coordinate(value):
    result = float(value)
    if not number(result, 0, 1):
        raise argparse.ArgumentTypeError("coordonnée normalisée entre 0 et 1")
    return result


def port(value):
    result = int(value)
    if not 1024 <= result <= 65535:
        raise argparse.ArgumentTypeError("port local entre 1024 et 65535")
    return result


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="mgm-ios-kali phone", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    descriptions = {
        "status": "vérifier la connexion et le pilote XCTest",
        "capture": "enregistrer une image PNG locale",
        "read": "lire les libellés visibles de l’accessibilité",
        "live": "afficher l’écran via le service développeur Apple",
        "tap": "appuyer sur un point de l’écran",
        "press": "appuyer pendant 0,5 seconde",
        "swipe": "glisser entre deux points",
        "type": "saisir un texte depuis le terminal",
        "home": "revenir à l’écran d’accueil",
        "launch": "ouvrir une application par son identifiant",
    }
    gestures = {"tap", "press", "swipe", "type", "home", "launch"}
    for name, description in descriptions.items():
        command = commands.add_parser(name, help=description, description=description)
        command.add_argument("--device", type=udid, required=True, metavar="UDID")
        command.set_defaults(gesture=name in gestures)
        if name in gestures:
            command.add_argument("--reference", required=True, type=Path, metavar="PNG",
                                 help="capture de référence prise sur cet iPhone")
        if name in {"tap", "press", "swipe"}:
            for axis in ("x", "y"):
                command.add_argument(axis, type=coordinate)
        if name == "swipe":
            command.add_argument("to_x", type=coordinate)
            command.add_argument("to_y", type=coordinate)
        elif name == "capture":
            command.add_argument("output", type=Path, metavar="PNG")
        elif name == "read":
            command.add_argument("--query", help="filtrer les libellés")
        elif name == "launch":
            command.add_argument("bundle", metavar="BUNDLE")
        elif name == "live":
            command.add_argument("--ios", required=True, type=Path, help="exécutable go-ios")
            command.add_argument("--tunnel-port", required=True, type=port)
            command.add_argument("--label", default="iPhone USB")
            command.add_argument("--interval", type=float, choices=(.5, .75, 1, 2), default=.75)
    return parser.parse_args(argv)


def save_capture(destination, image):
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".mgm-capture-") as stage:
        stage.write(image)
        stage.flush()
        try:
            os.link(stage.name, destination)
        except FileExistsError as exc:
            raise Blocked("output-exists") from exc


def read_screen(phone, query):
    snapshot = phone.capture()
    screen = snapshot[1]
    text = phone.text()
    if phone.capture() != snapshot:
        raise Blocked("stale")
    found = []
    for item in text:
        x = item["x"] / screen["width"]
        y = item["y"] / screen["height"]
        if number(x, 0, 1) and number(y, 0, 1) and (not query or query.casefold() in item["text"].casefold()):
            found.append({**item, "x": x, "y": y})
    return {"screen": screen, "text": found}


def perform_gesture(phone, args):
    snapshot = phone.capture()
    image, screen = snapshot
    with args.reference.open("rb") as reference:
        if reference.read(len(image) + 1) != image:
            raise Blocked("stale")

    text = None
    if args.command == "type":
        text = getpass.getpass("Texte à saisir sur l’iPhone > ")
        if not 0 < len(text) <= 200 or not text.isprintable():
            raise Blocked("invalid-text")
    print(f"Exécuter « {args.command} » sur {screen['app']} ? [o/N] ", end="", file=sys.stderr, flush=True)
    if input().strip().lower() not in {"o", "oui"}:
        raise Blocked("cancelled")

    if phone.capture() != snapshot:
        raise Blocked("stale")
    if phone.prepare_action(args.command) and phone.capture() != snapshot:
        raise Blocked("stale")

    def point(x, y):
        return min(x * screen["width"], screen["width"] - 1), min(y * screen["height"], screen["height"] - 1)

    match args.command:
        case "tap":
            phone.tap(*point(args.x, args.y))
        case "press":
            x, y = point(args.x, args.y)
            phone.press(x, y, 0.5)
        case "swipe":
            phone.drag(*point(args.x, args.y), *point(args.to_x, args.to_y))
        case "home":
            phone.home()
        case "launch":
            phone.launch(args.bundle)
        case "type":
            phone.type_text(text)
    return {"state": "ok", "action": args.command}


def run(args):
    if sys.platform != "linux":
        raise Blocked("linux-required")
    if args.command == "live":
        if not args.ios.is_file() or not os.access(args.ios, os.X_OK):
            raise Blocked("go-ios-required")
        try:
            import live_kali
        except ImportError as exc:
            raise Blocked("viewer-dependencies-required") from exc
        try:
            live_kali.run(args)
        except live_kali.tk.TclError as exc:
            raise Blocked("display-required") from exc
        return None

    if args.gesture and (not sys.stdin.isatty() or not sys.stderr.isatty()):
        raise Blocked("terminal-required")
    phone = UsbIPhone(args.device)
    state = phone.state()
    if args.command == "status":
        return {"state": state}
    if args.command == "read":
        return read_screen(phone, args.query)
    if args.command == "capture":
        image, screen = phone.capture()
        save_capture(args.output, image)
        return {"screen": screen, "output": str(args.output)}
    return perform_gesture(phone, args)


def main(argv=None):
    args = parse_args(argv)
    try:
        result = run(args)
    except Blocked as exc:
        print(json.dumps({"state": exc.code}))
        return 1
    except (KeyboardInterrupt, EOFError):
        print(json.dumps({"state": "interrupted"}))
        return 130
    except OSError:
        print(json.dumps({"state": "file-io"}))
        return 1
    if result is not None:
        print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
