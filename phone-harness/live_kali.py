"""Local live iPhone viewer using Apple's developer screenshot service."""
from __future__ import annotations

import datetime
import queue
import subprocess
import tempfile
import threading
import tkinter as tk
from pathlib import Path

from PIL import Image, ImageTk


def capture_loop(args, udid, frames, stop, running):
    with tempfile.TemporaryDirectory(prefix="mgm-live-kali-") as workspace:
        path = Path(workspace, "frame.png")
        command = [str(args.ios.resolve()), "screenshot", f"--output={path}", f"--udid={udid}",
                   f"--tunnel-info-port={args.tunnel_port}", "--tunnel-info-host=127.0.0.1"]
        while not stop.is_set():
            if not running.wait(.3):
                continue
            try:
                path.unlink(missing_ok=True)
                result = subprocess.run(command, cwd=workspace, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=6, check=False)
                if result.returncode or not 0 < path.stat().st_size <= 12_000_000:
                    raise OSError("capture")
                with Image.open(path, formats=("PNG",)) as image:
                    if max(image.size) > 8192 or image.width * image.height > 16_000_000:
                        raise OSError("dimensions")
                    frame = image.convert("RGB")
                stamp = datetime.datetime.now().astimezone().strftime("%H:%M:%S")
            except (OSError, ValueError, subprocess.SubprocessError, Image.DecompressionBombError):
                frame, stamp = None, None
            if running.is_set():
                try:
                    frames.get_nowait()
                except queue.Empty:
                    pass
                frames.put_nowait((frame, stamp))
            stop.wait(args.interval)


def run(args):
    root = tk.Tk()
    root.title("MGM Téléphone — iPhone en direct")
    height = min(round(root.winfo_screenheight() * .86), 920)
    width = max(340, round(height * .47))
    root.geometry(f"{width}x{height}")
    root.minsize(320, 420)
    root.configure(background="#101418")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)

    bar = tk.Frame(root, background="#20282e", padx=12, pady=9)
    bar.grid(row=0, column=0, sticky="ew")
    name = tk.Label(bar, text=args.label, bg="#20282e", fg="#f4f6f6",
                    font=("Sans", 11, "bold"), anchor="w")
    name.pack(side="left", fill="x", expand=True)
    canvas = tk.Label(root, text="Attente de la capture USB…", bg="#101418", fg="#b7c6cb")
    canvas.grid(row=1, column=0, sticky="nsew", padx=8, pady=5)
    status = tk.StringVar(value="Connexion USB")
    tk.Label(root, textvariable=status, bg="#20282e", fg="#d9e1e4", padx=12, pady=6, anchor="w").grid(
        row=2, column=0, sticky="ew")

    frames = queue.Queue(maxsize=1)
    stop, running = threading.Event(), threading.Event()
    running.set()
    def pause():
        if running.is_set():
            running.clear()
            button.configure(text="Reprendre")
            status.set("En pause")
        else:
            running.set()
            button.configure(text="Pause")
            status.set("Attente de la capture USB…")

    button = tk.Button(bar, text="Pause", command=pause, padx=7, pady=1)
    button.pack(side="right")
    received = 0

    def show():
        nonlocal received
        try:
            frame, stamp = frames.get_nowait()
        except queue.Empty:
            frame = stamp = None
        else:
            if running.is_set() and frame is None:
                status.set("Capture USB indisponible")
            elif running.is_set():
                if received < 2:
                    print(f"Image reçue à {stamp} ({frame.width}×{frame.height})", flush=True)
                received += 1
                frame.thumbnail((max(1, root.winfo_width() - 16), max(1, root.winfo_height() - 85)))
                image = ImageTk.PhotoImage(frame)
                canvas.configure(image=image, text="")
                canvas.image = image
                status.set(f"En direct · image reçue à {stamp}")
        root.after(150, show)

    def close():
        stop.set()
        running.set()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", close)
    thread = threading.Thread(target=capture_loop, args=(args, args.device, frames, stop, running), daemon=True)
    thread.start()
    root.after(150, show)
    root.lift()
    root.mainloop()
    thread.join(timeout=7)
