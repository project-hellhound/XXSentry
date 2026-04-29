#!/bin/bash
# update.sh — High-Fidelity Update for xssentry v4.0 [HELLHOUND-class]

# Zero-dependency Python HUD for immediate animation start
python3 - << 'EOF'
import sys
import time
import math
import threading
import subprocess
import shutil
import os

# ------ CONFIGURATION & ASSETS ------
_BRAILLE_WAVE = ["⠁", "⠃", "⠇", "⡇", "⣇", "⣧", "⣷", "⣿", "⣾", "⣶", "⣦", "⣄", "⡄", "⠄", "⠀", "⠀"]

def get_terminal_width():
    try:
        return shutil.get_terminal_size().columns
    except:
        return 80

def case_wave_ansi(text, frame):
    """Simple ANSI-based case-wave effect."""
    result = ""
    for i, ch in enumerate(text):
        if ch == " ":
            result += " "
            continue
        val = math.sin(i * 0.45 + frame * 4.5)
        if val > 0.7:
            result += f"\033[1;31m{ch.upper()}\033[0m"
        elif val > 0.3:
            result += f"\033[31m{ch.upper()}\033[0m"
        elif val > -0.1:
            result += f"\033[31m{ch}\033[0m"
        else:
            result += f"\033[2;31m{ch.lower()}\033[0m"
    return result

def draw_ui(text, stop_event):
    """Animates a single-line HUD using pure ANSI (Zero Dependencies)."""
    n = len(_BRAILLE_WAVE)
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()
    try:
        while not stop_event.is_set():
            t = time.time()
            tw = get_terminal_width()
            txt = case_wave_ansi(text, t)
            wave_width = (tw - len(text) - 10) // 2
            if wave_width < 2:
                sys.stdout.write(f"\r{txt}")
            else:
                left_chars = "".join(_BRAILLE_WAVE[int((i * 1.5 - t * 18)) % n] for i in range(wave_width))
                right_chars = "".join(_BRAILLE_WAVE[int(((wave_width - i) * 1.5 + t * 18)) % n] for i in range(wave_width))
                sys.stdout.write(f"\r\033[1;31m{left_chars}\033[0m  {txt}  \033[1;31m{right_chars}\033[0m")
            sys.stdout.flush()
            time.sleep(0.04)
    finally:
        sys.stdout.write("\r\033[K\033[?25h")
        sys.stdout.flush()

def run_task(text, cmd):
    """Runs a task with the immediate animation."""
    stop_event = threading.Event()
    t = threading.Thread(target=draw_ui, args=(text, stop_event), daemon=True)
    t.start()
    try:
        subprocess.run(cmd, shell=True, capture_output=True)
    finally:
        stop_event.set()
        t.join()

def main():
    run_task("SYNCING WITH REMOTE CLOUD", "git fetch --all && git reset --hard origin/main")
    if os.path.exists(".venv"):
        run_task("OPTIMIZING VIRTUAL ENVIRONMENT", "./.venv/bin/pip install --upgrade pip && ./.venv/bin/pip install -e .")
    print("\n\033[1;32m[+] THE SENTRY HAS BEEN RE-ARMED\033[0m")
    print("\033[2mVERSION: 4.0.0-STABLE\033[0m\n")

if __name__ == "__main__":
    main()
EOF
