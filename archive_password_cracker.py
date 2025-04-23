"""
archive_password_cracker.py – GUI front‑end for ArchivePasswordCrackerCLI
Added features:
  • Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z undo‑redo on every text entry
  • Drag‑and‑drop a file onto the Archive File entry (Windows – optional *windnd*)
  • Skip previously tried passwords (using C++ Bloom Filter state)
"""

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path
import datetime
import subprocess
import threading
import time
import customtkinter as ctk
import ctypes
# from ctypes import wintypes # Not strictly needed if not using MonitorFromPoint directly
import traceback
import platform
import json
from ctypes import wintypes

# ──────────────────────────────────────────────────────────────────────
# OPTIONAL: drag‑and‑drop support (Windows only, via *windnd*)
# ──────────────────────────────────────────────────────────────────────
try:
    import windnd
    HAS_WINDND = True
except ImportError:
    HAS_WINDND = False
    print("Optional dependency 'windnd' not found. Drag & drop disabled.")

# ──────────────────────────────────────────────────────────────────────
# DPI awareness helpers (No changes needed)
# ──────────────────────────────────────────────────────────────────────
try:
    if platform.system() == "Windows":
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
except AttributeError:
    try:
        if platform.system() == "Windows":
            ctypes.windll.user32.SetProcessDPIAware()
    except AttributeError:
        pass


def get_scaling_factor() -> float:
    # Simplified scaling factor logic (assuming it works as before)
    if platform.system() != "Windows": return 1.0
    try:
        # Attempt modern DPI awareness check first
        PROCESS_PER_MONITOR_DPI_AWARE = 2
        shcore = ctypes.windll.shcore
        dpi = ctypes.c_uint()
        # Get DPI for the monitor associated with the point (0,0) - usually primary
        monitor = ctypes.windll.user32.MonitorFromPoint(ctypes.wintypes.POINT(0, 0), 2) # MONITOR_DEFAULTTOPRIMARY
        shcore.GetDpiForMonitor(monitor, 0, ctypes.byref(dpi), ctypes.byref(dpi)) # MDT_EFFECTIVE_DPI = 0
        return dpi.value / 96.0
    except Exception:
         # Fallback to older method if shcore fails
        try:
            hdc = ctypes.windll.user32.GetDC(0)
            LOGPIXELSX = 88
            dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, LOGPIXELSX)
            ctypes.windll.user32.ReleaseDC(0, hdc)
            return dpi / 96.0
        except Exception:
             return 1.0 # Default if everything fails

# ──────────────────────────────────────────────────────────────────────
# Resource helper (No changes needed)
# ──────────────────────────────────────────────────────────────────────
def resource_path(relative_path: str) -> str:
    """
    Returnează calea absolută către o resursă, indiferent
    că rulăm din sursă, dintr-un build --onedir sau --onefile.
    """
    # 1. Build onefile? atunci PyInstaller dezarhivează tot într‑un temp
    if getattr(sys, '_MEIPASS', None):
        base_path = sys._MEIPASS # type: ignore[attr-defined]
    # 2. Build onedir? atunci helper-ele stau lângă executabil
    elif getattr(sys, 'frozen', False):
        base_path = os.path.dirname(sys.executable)
    # 3. Modul “dev”, sursă Python
    else:
        base_path = os.path.abspath(os.path.dirname(__file__))
    return os.path.join(base_path, relative_path)

def load_json_list(fname):
    path = resource_path(os.path.join("helpers", "json", fname))
    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip(): return []
            return json.loads(content)
    except json.JSONDecodeError as e:
         print(f"[Error] Failed to decode JSON from {fname}: {e}")
         return []
    except FileNotFoundError:
         print(f"[Warning] File not found: {path}")
         return []
    except Exception as e:
        print(f"[Warning] Could not load {fname} from {path}: {e}")
        return []
    
def parse_pattern(pattern):
    """Parse the pattern into segments, handling escape characters."""
    segments = []
    literal = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == '\\' and i + 1 < len(pattern):
            next_c = pattern[i + 1]
            if next_c in ['?', '*', '\\']:
                literal += next_c
                i += 1
            else:
                literal += c
        elif c in ['?', '*']:
            if literal:
                segments.append(literal)
                literal = ""
            segments.append(c)
        else:
            literal += c
        i += 1
    if literal:
        segments.append(literal)
    return segments

def calculate_pattern_properties(segments):
    """Calculate default min length and check for '*' presence."""
    min_len = 0
    contains_star = False
    for seg in segments:
        if seg == '?':
            min_len += 1
        elif seg == '*':
            contains_star = True
        else:  # literal
            min_len += len(seg)
    return min_len, contains_star


# Load default values
charset_map = load_json_list("charset_map.json")
min_length_map = load_json_list("min_length_map.json")
max_length_map = load_json_list("max_length_map.json")
archive_file_map = load_json_list("archive_file_map.json")


# ──────────────────────────────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────────────────────────────
app_instance = None

CPP_EXECUTABLE_NAME = (
    "ArchivePasswordCrackerCLI.exe"
    if platform.system() == "Windows"
    else "ArchivePasswordCrackerCLI"
)
CPP_EXECUTABLE_PATH = resource_path(os.path.join("helpers", CPP_EXECUTABLE_NAME))
# --- NEW: Skip list file path ---
SKIP_LIST_FILENAME = "skip_list.bf" # Bloom Filter file
SKIP_LIST_PATH = resource_path(os.path.join("helpers", SKIP_LIST_FILENAME))
# --- END NEW ---


def safe_update(cb, *args):
    """Thread‑safe Tk update"""
    global app_instance
    if app_instance and app_instance.winfo_exists():
        try:
            app_instance.after(0, cb, *args)
        except (RuntimeError, tk.TclError):
            pass # Ignore if window is closing
        except Exception as e:
            print(f"safe_update error: {e}")

from ctypes import wintypes, byref, sizeof, Structure

class RECT(Structure):
    _fields_ = [
        ('left',   wintypes.LONG),
        ('top',    wintypes.LONG),
        ('right',  wintypes.LONG),
        ('bottom', wintypes.LONG),
    ]

class MONITORINFO(Structure):
    _fields_ = [
        ('cbSize',    wintypes.DWORD),
        ('rcMonitor', RECT),
        ('rcWork',    RECT),
        ('dwFlags',   wintypes.DWORD),
    ]

def get_taskbar_offsets():
    """
    Returns (top, bottom, left, right) thickness of any app‑bars (e.g., the Windows taskbar)
    by comparing the monitor rectangle to its work‑area rectangle.
    """
    user32 = ctypes.windll.user32
    # Get handle to primary monitor (MONITOR_DEFAULTTOPRIMARY = 1)
    hMon = user32.MonitorFromPoint(wintypes.POINT(0, 0), 1)
    mi = MONITORINFO()
    mi.cbSize = sizeof(MONITORINFO)
    user32.GetMonitorInfoW(hMon, byref(mi))
    top_off    = mi.rcWork.top    - mi.rcMonitor.top
    bottom_off = mi.rcMonitor.bottom - mi.rcWork.bottom
    left_off   = mi.rcWork.left   - mi.rcMonitor.left
    right_off  = mi.rcMonitor.right - mi.rcWork.right
    return top_off, bottom_off, left_off, right_off

def get_work_area():
    """
    Returns (left, top, right, bottom) of the PRIMARY monitor's work area
    in **physical** pixels (i.e. screen minus taskbars).
    """
    user32 = ctypes.windll.user32
    hMon = user32.MonitorFromPoint(wintypes.POINT(0,0), 1)  # MONITOR_DEFAULTTOPRIMARY
    mi = MONITORINFO()
    mi.cbSize = sizeof(MONITORINFO)
    user32.GetMonitorInfoW(hMon, byref(mi))
    return (
        mi.rcWork.left,
        mi.rcWork.top,
        mi.rcWork.right,
        mi.rcWork.bottom,
    )

# ──────────────────────────────────────────────────────────
# Magic‑fudge divisor based on DPI scale
# ──────────────────────────────────────────────────────────
def get_center_divisor(scale: float,
                       ref_scale: float = 1.5,
                       ref_div:   float = 2.042) -> float:
    """
    Linear‐interpolate the “centering divisor” so that:
      * at scale==1.0 → divisor==2.0
      * at scale==ref_scale → divisor==ref_div
    """
    return 2.0 + (ref_div - 2.0) * (scale - 1.0) / (ref_scale - 1.0)

# ──────────────────────────────────────────────────────────────────────
# GUI
# ──────────────────────────────────────────────────────────────────────
class ArchivePasswordCrackerApp(ctk.CTk):
    # ════════════════════════════════════════════════════════════════
    # Init / layout
    # ════════════════════════════════════════════════════════════════
    def __init__(self):
        global app_instance
        super().__init__()
        app_instance = self

        self.backend_ok = Path(CPP_EXECUTABLE_PATH).is_file()

        self.title("Archive Password Cracker (GUI + C++ Backend)")
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # ──────────────────────────────────────────────────────────
        # Usage in your __init__ (instead of hardcoding “2.04”)
        # ──────────────────────────────────────────────────────────
# … inside your __init__ before self.geometry(…) …
        w, h     = 600, 555
        min_w, min_h = w, h

        scale    = get_scaling_factor()       # e.g. 1.0, 1.5, 2.0, ...
        scr_w    = self.winfo_screenwidth()
        scr_h    = self.winfo_screenheight()
        adj_w    = int(w * scale)
        adj_h    = int(h * scale)

        divisor = get_center_divisor(scale)
        x = int((scr_w - adj_w) / divisor)

        # your existing bottom‐hack is unchanged
        top, bottom, left, right = get_taskbar_offsets()
        y = int((scr_h - adj_h) / 2) - int(bottom * 0.85)

        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(min_w, min_h)

        # Main frame
        self.main = ctk.CTkFrame(self)
        self.main.pack(padx=15, pady=15, fill="both", expand=True)

        # Configure grid columns (allow inputs to expand more)
        self.main.grid_columnconfigure(0, weight=1) # Spacer left
        self.main.grid_columnconfigure(1, weight=0) # Labels
        self.main.grid_columnconfigure(2, weight=3) # Inputs (expand more)
        self.main.grid_columnconfigure(3, weight=0) # Buttons / Small controls
        self.main.grid_columnconfigure(4, weight=1) # Spacer right
        # Row for log needs to expand (will set later)

        row_idx = 0
        # ──────────────────────────────────────────────────────────
        # Charset
        # ──────────────────────────────────────────────────────────
        ctk.CTkLabel(self.main, text="Charset:").grid(
            row=row_idx, column=1, padx=(0,10), pady=5, sticky="e"
        )
        default_charset = charset_map[0] if charset_map else "abcdefghijklmnopqrstuvwxyz0123456789"
        self.charset_var = tk.StringVar(value=default_charset)
        self.charset_entry = ctk.CTkEntry(
            self.main, textvariable=self.charset_var, width=400
        )
        self.charset_entry.grid(
            row=row_idx, column=2, columnspan=2, padx=(0,10), pady=5, sticky="ew"
        )
        self._enable_undo_redo(self.charset_entry)
        row_idx += 1

        # ──────────────────────────────────────────────────────────
        # Min Length
        # ──────────────────────────────────────────────────────────
        self.minlen_label = ctk.CTkLabel(self.main, text="Min Length:")
        self.minlen_label.grid(row=row_idx, column=1, padx=(0, 10), pady=5, sticky="e")
        default_min_length = min_length_map[0] if min_length_map else "1"
        self.minlen_var = tk.StringVar(value=default_min_length)
        vcmd_int = (self.register(self._validate_positive_int), "%P")
        self.minlen_entry = ctk.CTkEntry(
            self.main, textvariable=self.minlen_var, width=80,
            validate="key", validatecommand=vcmd_int,
        )
        self.minlen_entry.grid(
            row=row_idx, column=2, padx=0, pady=5, sticky="w"
        )

        # Store normal colors for entries
        self._entry_bg_normal   = self.minlen_entry.cget("fg_color")
        self._entry_fg_normal   = self.minlen_entry.cget("text_color")
        self._enable_undo_redo(self.minlen_entry)
        row_idx += 1

        # ──────────────────────────────────────────────────────────
        # Max Length
        # ──────────────────────────────────────────────────────────
        self.maxlen_label = ctk.CTkLabel(self.main, text="Max Length:")
        self.maxlen_label.grid(row=row_idx, column=1, padx=(0, 10), pady=5, sticky="e")
        default_max_length = max_length_map[0] if max_length_map else "8"
        self.maxlen_var = tk.StringVar(value=default_max_length)
        self.maxlen_entry = ctk.CTkEntry(
            self.main, textvariable=self.maxlen_var, width=80,
            validate="key", validatecommand=vcmd_int,
        )
        self.maxlen_entry.grid(
            row=row_idx, column=2, padx=0, pady=5, sticky="w"
        )
        self._enable_undo_redo(self.maxlen_entry)
        row_idx += 1

        # We'll use these to gray-out locked fields

        # ──────────────────────────────────────────────────────────
        # Cracking Mode/Order
        # ──────────────────────────────────────────────────────────
        ctk.CTkLabel(self.main, text="Mode:").grid(
            row=row_idx, column=1, padx=(0,10), pady=5, sticky="e"
        )
        self.order_options = [ "Ascending (Min..Max)", "Descending (Max..Min)", "Pseudo-Random" ]
        self.order_map = { "Ascending (Min..Max)": "ascending", "Descending (Max..Min)": "descending", "Pseudo-Random": "random" }
        self.order_var = tk.StringVar(value=self.order_options[0])
        self.order_combo = ctk.CTkComboBox(
            self.main, variable=self.order_var, values=self.order_options, state="readonly", width=200
        )
        self.order_combo.grid( row=row_idx, column=2, padx=0, pady=5, sticky="w" )
        row_idx += 1

        # ──────────────────────────────────────────────────────────
        # Archive Path
        # ──────────────────────────────────────────────────────────
        ctk.CTkLabel(self.main, text="Archive File:").grid(
            row=row_idx, column=1, padx=(0,10), pady=5, sticky="e"
        )
        default_archive_file = archive_file_map[0] if archive_file_map else ""
        self.archive_path_var = tk.StringVar(value=default_archive_file)
        self.archive_entry = ctk.CTkEntry( self.main, textvariable=self.archive_path_var )
        self.archive_entry.grid( row=row_idx, column=2, padx=0, pady=5, sticky="ew" )
        self._enable_undo_redo(self.archive_entry)

        self.browse_btn = ctk.CTkButton(
            self.main, text="Browse…", width=90, command=self.browse_archive
        )
        self.browse_btn.grid(row=row_idx, column=3, padx=(10,10), pady=5, sticky="w")

        if HAS_WINDND:
            windnd.hook_dropfiles(self.archive_entry, func=self.on_archive_drop)
            self.archive_entry.configure(placeholder_text="Select or drag & drop archive")
        else:
            self.archive_entry.configure(placeholder_text="Select archive path")
        row_idx += 1


        # Pattern Matching Checkbox
        self.pattern_matching_var = tk.BooleanVar(value=False)
        self.pattern_checkbox = ctk.CTkCheckBox(
            self.main, text="Enable Pattern Matching", variable=self.pattern_matching_var
        )
        self.pattern_checkbox.grid(row=row_idx, column=1, columnspan=2, padx=(0,10), pady=5, sticky="w")
        row_idx += 1

        # Pattern Input
        self.pattern_label = ctk.CTkLabel(self.main, text="Pattern:")
        self.pattern_label.grid(row=row_idx, column=1, padx=(0, 10), pady=5, sticky="e")
        self.pattern_var = tk.StringVar(value="")
        self.pattern_entry = ctk.CTkEntry(self.main, textvariable=self.pattern_var, width=400)
        self.pattern_entry.grid(row=row_idx, column=2, columnspan=2, padx=(0,10), pady=5, sticky="ew")
        
        self._enable_undo_redo(self.pattern_entry)
        row_idx += 1

        self._entry_bg_normal = self.minlen_entry.cget("fg_color")
        self._entry_fg_normal = self.minlen_entry.cget("text_color")
        self._minlen_label_normal = self.minlen_label.cget("text_color")
        self._maxlen_label_normal = self.maxlen_label.cget("text_color")
        self._pattern_label_normal = self.pattern_label.cget("text_color")

        # Define disabled colors
        self._entry_bg_disabled = "#333333"  # Dark background for disabled state
        self._entry_fg_disabled = "#777777"  # Gray text for disabled state
        self._label_fg_disabled = "#777777"  # Gray text for disabled labels

        self.pattern_entry.configure(
            state="disabled",
            fg_color=self._entry_bg_disabled,
            text_color=self._entry_fg_disabled
        )
        self.pattern_label.configure(text_color=self._label_fg_disabled)        

        # --- NEW: Skip List Controls ---
        # ──────────────────────────────────────────────────────────
        # Skip List Checkbox & Clear Button
        # ──────────────────────────────────────────────────────────
        self.skip_var = tk.BooleanVar(value=True) # Default to ON
        skip_cb = ctk.CTkCheckBox(
            self.main,
            text="Exclude previously tried passwords (uses helpers/" + SKIP_LIST_FILENAME + ")",
            variable=self.skip_var
        )
        skip_cb.grid(row=row_idx, column=1, columnspan=2, padx=(0,10), pady=(10,5), sticky="w")

        self.clear_skip_btn = ctk.CTkButton(
             self.main, text="Clear Skip List", width=90, command=self.clear_skip_list
        )
        self.clear_skip_btn.grid(row=row_idx, column=3, padx=(10,10), pady=(10,5), sticky="w")
        row_idx += 1
        # --- END NEW ---


        # ──────────────────────────────────────────────────────────
        # Run / Stop buttons
        # ──────────────────────────────────────────────────────────
        self.btn_frame = ctk.CTkFrame(self.main, fg_color="transparent")
        self.btn_frame.grid(row=row_idx, column=1, columnspan=3, pady=(10,5), sticky="ew")
        self.btn_frame.grid_columnconfigure(0, weight=1) # Distribute space around buttons
        self.btn_frame.grid_columnconfigure(1, weight=0) # Run button
        self.btn_frame.grid_columnconfigure(2, weight=0) # Stop button
        self.btn_frame.grid_columnconfigure(3, weight=1) # Distribute space

        self.run_btn = ctk.CTkButton(
            self.btn_frame, text="Run C++ Backend", command=self.start_cracking, width=160
        )
        self.run_btn.grid(row=0, column=1, padx=(0, 10), pady=5) # Place run button left of center
        if not self.backend_ok:
            self.run_btn.configure(state="disabled")

        self.stop_btn = ctk.CTkButton(
            self.btn_frame, text="Stop Backend", command=self.stop_cracking, state="disabled", width=160
        )
        self.stop_btn.grid(row=0, column=2, padx=(10, 0), pady=5) # Place stop button right of center
        row_idx += 1

        # ──────────────────────────────────────────────────────────
        # Output Log Area
        # ──────────────────────────────────────────────────────────
        ctk.CTkLabel(self.main, text="Output Log:").grid(
            row=row_idx, column=1, columnspan=3, padx=(0,10), pady=(5,0), sticky="nw"
        )
        row_idx += 1 # Increment *before* configuring the row weight for the log

        self.status_txt = ctk.CTkTextbox(
            self.main, height=200, state="disabled", wrap="word", activate_scrollbars=True
        )
        self.status_txt.grid(
            row=row_idx, column=1, columnspan=3, padx=(0,10), pady=(0,10), sticky="nsew"
        )
        self.main.grid_rowconfigure(row_idx, weight=1) # Configure *this* row to expand vertically

        # ──────────────────────────────────────────────────────────
        # Runtime state
        # ──────────────────────────────────────────────────────────
        self.process = None
        self.stdout_thread = None
        self.stderr_thread = None
        self.running = False
        self.log_messages = []  # List to store log messages
        self.found_password = None
        self.stopped_by_user = False
        self.monitor_after_id = None

        self.pattern_var.trace("w", self.update_length_fields)
        self.pattern_matching_var.trace("w", self.update_length_fields)
        self.minlen_var.trace("w", self.validate_min_length)
        self.minlen_var.trace("w", self.validate_max_length)
        self.maxlen_var.trace("w", self.validate_max_length)



        self.update_status("Ready. Configure parameters and select an archive.")
        if not self.backend_ok:
            err_msg = f"C++ backend '{CPP_EXECUTABLE_NAME}' not found in 'helpers' folder."
            popup_msg = f"{err_msg}\n\nExpected at:\n{CPP_EXECUTABLE_PATH}\n\nPlease ensure it's compiled and placed correctly in the 'helpers' subfolder."
            self.update_status(f"[ERROR] {err_msg}")
            self.after(100, lambda: messagebox.showerror("Setup Error", popup_msg))

    def update_length_fields(self, *args):
        """Update min/max length fields, pattern entry, and their labels based on pattern matching state."""
        if not self.pattern_matching_var.get():
            # Pattern matching disabled: enable min/max, disable pattern
            self.minlen_entry.configure(
                state="normal",
                fg_color=self._entry_bg_normal,
                text_color=self._entry_fg_normal
            )
            self.maxlen_entry.configure(
                state="normal",
                fg_color=self._entry_bg_normal,
                text_color=self._entry_fg_normal
            )
            self.minlen_label.configure(text_color=self._minlen_label_normal)
            self.maxlen_label.configure(text_color=self._maxlen_label_normal)
            self.pattern_entry.configure(
                state="disabled",
                fg_color=self._entry_bg_disabled,
                text_color=self._entry_fg_disabled
            )
            self.pattern_label.configure(text_color=self._label_fg_disabled)
        else:
            # Pattern matching enabled: enable pattern
            self.pattern_entry.configure(
                state="normal",
                fg_color=self._entry_bg_normal,
                text_color=self._entry_fg_normal
            )
            self.pattern_label.configure(text_color=self._pattern_label_normal)
            pattern = self.pattern_var.get().strip()
            if not pattern:
                # Empty pattern: enable min/max
                self.minlen_entry.configure(
                    state="normal",
                    fg_color=self._entry_bg_normal,
                    text_color=self._entry_fg_normal
                )
                self.maxlen_entry.configure(
                    state="normal",
                    fg_color=self._entry_bg_normal,
                    text_color=self._entry_fg_normal
                )
                self.minlen_label.configure(text_color=self._minlen_label_normal)
                self.maxlen_label.configure(text_color=self._maxlen_label_normal)
                return
            segments = parse_pattern(pattern)
            default_min, contains_star = calculate_pattern_properties(segments)
            if contains_star:
                # Pattern has '*': enable min/max
                self.minlen_entry.configure(
                    state="normal",
                    fg_color=self._entry_bg_normal,
                    text_color=self._entry_fg_normal
                )
                self.maxlen_entry.configure(
                    state="normal",
                    fg_color=self._entry_bg_normal,
                    text_color=self._entry_fg_normal
                )
                self.minlen_label.configure(text_color=self._minlen_label_normal)
                self.maxlen_label.configure(text_color=self._maxlen_label_normal)
                try:
                    # Only check/set if the field is NOT empty
                    current_val_str = self.minlen_var.get()
                    if current_val_str: # Check if not empty
                        current_min = int(current_val_str)
                        if current_min < default_min:
                            # Field has a value, but it's too low for the pattern
                            self.minlen_var.set(str(default_min))
                        # else: Field has a valid value >= default_min, leave it.
                    # If it IS empty, do nothing here - let the user type or
                    # let validate_min_length handle it when a value is entered.
                except ValueError:
                    # Field has content, but it's not an integer. Reset to default_min.
                    # This handles cases where the field might contain invalid text
                    # when the pattern itself is changed.
                    self.minlen_var.set(str(default_min))
            else:
                # Pattern has no '*': disable min/max
                self.minlen_var.set(str(default_min))
                self.maxlen_var.set(str(default_min))
                self.minlen_entry.configure(
                    state="disabled",
                    fg_color=self._entry_bg_disabled,
                    text_color=self._entry_fg_disabled
                )
                self.maxlen_entry.configure(
                    state="disabled",
                    fg_color=self._entry_bg_disabled,
                    text_color=self._entry_fg_disabled
                )
                self.minlen_label.configure(text_color=self._label_fg_disabled)
                self.maxlen_label.configure(text_color=self._label_fg_disabled)

    def validate_min_length(self, *args):
        """Ensure min length is >= default_min when pattern matching is enabled with '*'."""
        if not self.pattern_matching_var.get():
            return # Only validate when pattern matching is on

        pattern = self.pattern_var.get().strip()
        if not pattern:
            return # No pattern, no pattern-specific validation needed

        segments = parse_pattern(pattern)
        default_min, contains_star = calculate_pattern_properties(segments)

        if contains_star: # Only enforce if pattern has '*' (otherwise lengths are fixed by pattern)
            current_val_str = self.minlen_var.get()

            if current_val_str == "":
                # Allow empty string temporarily during typing
                # The final check happens in start_cracking or when a value is entered
                return

            try:
                min_len = int(current_val_str)
                if min_len <= 0: # Also ensure positive value if basic validation missed it
                    self.minlen_var.set(str(default_min))
                elif min_len < default_min:
                    # Value is valid but too low, reset to minimum allowed by pattern
                    self.minlen_var.set(str(default_min))
                # else: Value is valid and >= default_min, leave it as is
            except ValueError:
                # Value is not empty but not a valid integer (e.g., user typed text)
                # Reset to the default minimum derived from the pattern
                self.minlen_var.set(str(default_min))

    def validate_max_length(self, *args):
        """Ensure max length is >= min length."""
        current_max_str = self.maxlen_var.get()
        current_min_str = self.minlen_var.get()

        if current_max_str == "" or current_min_str == "":
             # Allow empty string temporarily during typing
             return

        try:
            min_len = int(current_min_str)
            max_len = int(current_max_str)
            if max_len < min_len:
                # Max is valid but less than min, set max = min
                self.maxlen_var.set(str(min_len))
            elif max_len <= 0: # Ensure positive value if basic validation missed it
                 # Max is not positive, try resetting based on min_len if min_len is valid > 0
                 if min_len > 0:
                     self.maxlen_var.set(str(min_len))
                 else:
                     # Fallback if min_len is also invalid (e.g., 0 or negative somehow)
                     # This case is less likely with pattern validation, but good to have a fallback
                     self.maxlen_var.set("1") # Set to a basic default like 1
        except ValueError:
            # One of the fields is not empty but not a valid integer.
            # We could try to reset max based on min, but it's complex if min is also invalid.
            # For simplicity, we might just let the start_cracking validation catch this,
            # or reset max_len to a default if min_len is valid.
            try:
                 min_len = int(current_min_str)
                 if min_len > 0:
                     self.maxlen_var.set(str(min_len)) # Reset max to valid min
                 # else: min is also invalid, leave max as is for now
            except ValueError:
                 pass # Both fields potentially invalid, start_cracking will handle.



    # ════════════════════════════════════════════════════════════════
    # Utility – undo / redo support (No changes needed)
    # ════════════════════════════════════════════════════════════════
    def _enable_undo_redo(self, ctk_entry: ctk.CTkEntry):
        internal = getattr(ctk_entry, "_entry", None) or getattr(ctk_entry, "entry", ctk_entry)
        try:
            internal.configure(undo=True, autoseparators=True, maxundo=-1)
            internal.bind("<Control-z>", lambda e: internal.edit_undo())
            internal.bind("<Control-y>", lambda e: internal.edit_redo())
            internal.bind("<Control-Shift-Z>", lambda e: internal.edit_redo())
        except tk.TclError:  # Entry widget without built‑in undo
            internal._undo_stack = [internal.get()]
            internal._undo_index = 0

            def record(event=None):
                val = internal.get()
                if val != internal._undo_stack[internal._undo_index]:
                    internal._undo_stack = internal._undo_stack[:internal._undo_index+1]
                    internal._undo_stack.append(val)
                    internal._undo_index += 1

            def undo(event=None):
                if internal._undo_index > 0:
                    internal._undo_index -= 1
                    internal.delete(0, tk.END)
                    internal.insert(0, internal._undo_stack[internal._undo_index])
                return "break"

            def redo(event=None):
                if internal._undo_index < len(internal._undo_stack) - 1:
                    internal._undo_index += 1
                    internal.delete(0, tk.END)
                    internal.insert(0, internal._undo_stack[internal._undo_index])
                return "break"

            internal.bind("<KeyRelease>", record)
            internal.bind("<Control-z>", undo)
            internal.bind("<Control-y>", redo)
            internal.bind("<Control-Shift-Z>", redo)

    # ════════════════════════════════════════════════════════════════
    # Drag‑and‑drop handler (No changes needed)
    # ════════════════════════════════════════════════════════════════
    def on_archive_drop(self, files):
        try:
            if not files: return
            # Decode bytes to UTF-8 string
            path = files[0].decode("utf-8", errors='ignore')
            if os.path.isfile(path):
                self.archive_path_var.set(path)
                self.update_status(f"Archive dropped: {os.path.basename(path)}")
            else:
                self.update_status(f"Dropped item is not a file: {path}")
                safe_update(messagebox.showwarning, "Invalid Drop", "Please drop a file, not a folder.")
        except Exception as e:
            self.update_status(f"Error processing drop: {e}")
            safe_update(messagebox.showerror, "Drop Error", f"Could not process dropped item:\n{e}")

    # ════════════════════════════════════════════════════════════════
    # Status textbox utility (No changes needed)
    # ════════════════════════════════════════════════════════════════
    def update_status(self, msg: str):
        if not self or not hasattr(self, 'status_txt') or not self.status_txt.winfo_exists():
            print(f"DBG Status Update (No GUI): {msg}")
            return
        try:
            self.status_txt.configure(state="normal")
            ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            lines = str(msg).strip().splitlines()
            for line in lines:
                log_entry = f"[{ts}] {line.strip()}"
                self.status_txt.insert(tk.END, log_entry + "\n")
                self.log_messages.append(log_entry)  # Store the log entry
            self.status_txt.see(tk.END)
            self.status_txt.configure(state="disabled")
        except (RuntimeError, tk.TclError):
            pass
        except Exception as e:
            print(f"Error updating status log: {e}")

    def save_log_to_file(self):
        log_file_path = resource_path(os.path.join("helpers", "log.txt"))  # Save in the same directory as the script
        try:
            with open(log_file_path, 'w', encoding='utf-8') as f:
                for log_entry in self.log_messages:
                    f.write(log_entry + "\n")
            self.update_status(f"Log saved to {log_file_path}")
        except Exception as e:
            self.update_status(f"Error saving log to file: {e}")


    # ════════════════════════════════════════════════════════════════
    # UI helpers
    # ════════════════════════════════════════════════════════════════
    def _validate_positive_int(self, P):
        # Allow empty string (for clearing field) or positive integers
        return (P.isdigit() and int(P) > 0) or P == ""

    def browse_archive(self):
        ft = [("Archive Files", "*.zip *.rar *.7z *.tar *.gz *.bz2"), ("All Files", "*.*")]
        # Use initialdir if a path is already set
        initial_dir = os.path.dirname(self.archive_path_var.get()) if self.archive_path_var.get() else "."
        p = filedialog.askopenfilename(title="Select Encrypted Archive File", filetypes=ft, initialdir=initial_dir)
        if p:
            self.archive_path_var.set(p)

    # --- NEW: Clear Skip List Function ---
    def clear_skip_list(self):
        global SKIP_LIST_PATH
        if os.path.isfile(SKIP_LIST_PATH):
            try:
                if messagebox.askyesno("Confirm Clear",
                                       f"This will delete the file:\n{SKIP_LIST_PATH}\n\n"
                                       "Previously tried passwords for the next run will NOT be skipped.\n"
                                       "Are you sure?", icon='warning'):
                    os.remove(SKIP_LIST_PATH)
                    self.update_status(f"Skip list file '{SKIP_LIST_FILENAME}' removed.")
                    messagebox.showinfo("Cleared", f"Skip list file '{SKIP_LIST_FILENAME}' removed successfully.")
            except OSError as e:
                self.update_status(f"Error removing skip list file: {e}")
                messagebox.showerror("Error", f"Could not remove skip list file:\n{e}")
        else:
            self.update_status(f"Skip list file '{SKIP_LIST_FILENAME}' does not exist.")
            messagebox.showinfo("Not Found", f"Skip list file '{SKIP_LIST_FILENAME}' does not exist.")
    # --- END NEW ---


    def set_ui_state(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        try:
            self.charset_entry.configure(state=state)
            self.pattern_checkbox.configure(state=state)
            if enabled:
                # Restore based on pattern matching state
                self.update_length_fields()
            else:
                # Disable all entries and gray out labels
                self.minlen_entry.configure(
                    state="disabled",
                    fg_color=self._entry_bg_disabled,
                    text_color=self._entry_fg_disabled
                )
                self.maxlen_entry.configure(
                    state="disabled",
                    fg_color=self._entry_bg_disabled,
                    text_color=self._entry_fg_disabled
                )
                self.pattern_entry.configure(
                    state="disabled",
                    fg_color=self._entry_bg_disabled,
                    text_color=self._entry_fg_disabled
                )
                self.minlen_label.configure(text_color=self._label_fg_disabled)
                self.maxlen_label.configure(text_color=self._label_fg_disabled)
                self.pattern_label.configure(text_color=self._label_fg_disabled)
            self.order_combo.configure(state=state)
            self.archive_entry.configure(state=state)
            self.browse_btn.configure(state=state)
            # Find the checkbox widget for skip list
            for widget in self.main.winfo_children():
                if isinstance(widget, ctk.CTkCheckBox) and "Exclude" in widget.cget("text"):
                    widget.configure(state=state)
                    break
            self.clear_skip_btn.configure(state=state)
            self.run_btn.configure(state="normal" if enabled and self.backend_ok else "disabled")
            self.stop_btn.configure(state="disabled" if enabled else "normal")
        except (RuntimeError, tk.TclError):
            pass
        except Exception as e:
            print(f"Error setting UI state: {e}")
    # ════════════════════════════════════════════════════════════════
    # Core – launch / monitor / stop C++ backend
    # ════════════════════════════════════════════════════════════════
    def start_cracking(self):
        if self.running: safe_update(messagebox.showwarning, "Busy", "Backend is already running."); return
        if not self.backend_ok: safe_update(messagebox.showerror, "Error", "C++ backend not found."); return

        # --- Validate Inputs ---
        charset = self.charset_var.get().strip()
        minlen_str = self.minlen_var.get().strip()
        maxlen_str = self.maxlen_var.get().strip()
        arc_path_str = self.archive_path_var.get().strip()
        order_selection = self.order_var.get()
        use_skip_list = self.skip_var.get() # <-- Get skip list state

        if not charset: safe_update(messagebox.showerror, "Input Error", "Charset cannot be empty."); return
        try:
            min_len = int(minlen_str)
            max_len = int(maxlen_str)
            if min_len <= 0: raise ValueError("Min length must be positive.")
            if max_len <= 0: raise ValueError("Max length must be positive.")
            if min_len > max_len: raise ValueError("Min length cannot be greater than Max length.")
        except ValueError as e: safe_update(messagebox.showerror, "Input Error", f"Invalid Length: {e}. Please enter positive numbers."); return

        try:
            arc_path_obj = Path(arc_path_str).expanduser()
            if not arc_path_obj.is_file(): raise FileNotFoundError("Specified path is not a file or does not exist.")
            arc_path_abs = str(arc_path_obj.resolve()) # Use absolute path for C++
        except Exception as e: safe_update(messagebox.showerror, "Input Error", f"Invalid Archive File Path:\n'{arc_path_str}'\n{e}"); return

        mode_arg = self.order_map.get(order_selection, "ascending") # Default to ascending if somehow invalid

        # --- Prepare Launch ---
        self.running = True; self.found_password = None; self.stopped_by_user = False
        self.set_ui_state(False);
        try:
            self.status_txt.configure(state="normal"); self.status_txt.delete("1.0", tk.END); self.status_txt.configure(state="disabled")
        except Exception as e: print(f"Error clearing status text: {e}")
        if self.monitor_after_id:
            try: self.after_cancel(self.monitor_after_id);
            except Exception: pass
            self.monitor_after_id = None

        self.update_status(f"Launching backend: {Path(CPP_EXECUTABLE_PATH).name}...")

        # --- Construct Command (with optional skip list args) ---
        cmd = [
            CPP_EXECUTABLE_PATH,
            charset,
            str(min_len),
            str(max_len),
            arc_path_abs,
            mode_arg
        ]
        # --- NEW: Add skip list arguments if checkbox is ticked ---
        if use_skip_list:
            global SKIP_LIST_PATH
            # --- CHANGE THIS VALUE ---
            checkpoint_interval_sec = "10" # Checkpoint every 10 seconds (was 15)
            # --- END CHANGE ---
            cmd.extend(["--skip-file", SKIP_LIST_PATH])
            cmd.extend(["--checkpoint-interval", checkpoint_interval_sec])
            self.update_status(f"Skip list enabled: {SKIP_LIST_FILENAME} (Checkpoint: {checkpoint_interval_sec}s)")
        # --- END NEW ---


        if self.pattern_matching_var.get():
            pattern = self.pattern_var.get().strip()
            if not pattern:
                safe_update(messagebox.showerror, "Input Error", "Pattern cannot be empty when pattern matching is enabled.")
                return
            cmd.extend(["--pattern", pattern])

        self.update_status(f"Params: Charset='{charset}', Len={min_len}-{max_len}, Mode={mode_arg}")
        # self.update_status(f"Full Command (DEBUG): {' '.join(cmd)}") # Uncomment for debugging command

        # --- Launch Process ---
        creationflags = 0; startupinfo = None; process_cwd = Path(CPP_EXECUTABLE_PATH).parent
        if platform.system() == "Windows":
            # Hide console window for C++ process
            creationflags=subprocess.CREATE_NO_WINDOW
            startupinfo=subprocess.STARTUPINFO()
            startupinfo.dwFlags|=subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow=subprocess.SW_HIDE
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", # Ensure UTF-8 decoding
                bufsize=1, # Line buffered
                creationflags=creationflags, startupinfo=startupinfo,
                cwd=process_cwd # Set CWD to 'helpers' so C++ can find '../bin/7z.exe'
            )
        except FileNotFoundError:
             err = f"Launch Error: C++ Executable not found at\n{CPP_EXECUTABLE_PATH}"; self.update_status(f"[ERROR] {err}"); safe_update(messagebox.showerror, "Launch Error", err); self.running = False; self.set_ui_state(True); return
        except OSError as e: # Catch other OS errors like permission denied
             err = f"Launch Error: Could not start C++ process.\n{e}"; self.update_status(f"[ERROR] {err}"); safe_update(messagebox.showerror, "Launch Error", err); self.running = False; self.set_ui_state(True); return
        except Exception as e:
             err = f"Unexpected Launch Error: {e}"; self.update_status(f"[ERROR] {err}"); safe_update(messagebox.showerror, "Launch Error", err); self.running = False; self.set_ui_state(True); return

        self.update_status(f"Backend process started (PID: {self.process.pid}).")

        # --- Start Reader Threads ---
        self.stdout_thread = threading.Thread(target=self._read_stream, args=(self.process.stdout, "stdout"), daemon=True); self.stdout_thread.start()
        self.stderr_thread = threading.Thread(target=self._read_stream, args=(self.process.stderr, "stderr"), daemon=True); self.stderr_thread.start()
        self._monitor_process() # Start polling for process exit

    def _read_stream(self, stream, tag):
        """ Reads output stream line by line and passes to handler """
        try:
            # The 'for line in stream' loop handles blocking reads efficiently
            for line in iter(stream.readline, ''):
                if not self.running and not self.process: break # Exit if process stopped externally
                ln = line.strip();
                if ln: safe_update(self.handle_backend_output, ln, tag)
            # Stream closed
        except ValueError:
             print(f"Stream {tag} closed (ValueError).") # Can happen during shutdown
        except Exception as e:
             # Avoid printing errors if we stopped intentionally
             if self.running or not self.stopped_by_user:
                 print(f"Stream reader error ({tag}): {e}")
                 safe_update(self.update_status, f"[WARN] Error reading {tag}: {e}")
        finally:
            try: stream.close()
            except Exception: pass
            # print(f"{tag} reader thread finished.")


    def handle_backend_output(self, line: str, tag: str):
        """ Process lines received from C++ stdout/stderr """
        if not self or not self.winfo_exists(): return # Exit if GUI is gone

        # Log everything unless it's the special FOUND marker
        if not line.startswith("FOUND:"):
             self.update_status(line) # Log regular output

        # Check for the password found signal
        if tag == "stdout" and line.startswith("FOUND:") and self.running and not self.found_password:
             self.found_password = line[len("FOUND:") :].strip()
             # Optionally, log the found password here too, masked or clear
             self.update_status(f"🔑 SUCCESS: Password found: {self.found_password}")
             # No need to stop here, monitor_process handles termination & popup

    def _monitor_process(self):
        """ Periodically checks if the C++ process has exited """
        if not self or not self.winfo_exists(): return # Stop if window closed
        if not self.running or not self.process:
             # Ensure UI is re-enabled if monitoring stops unexpectedly while not running
             if not self.stopped_by_user: self.set_ui_state(True)
             return

        try:
            code = self.process.poll()
        except Exception as e:
            self.update_status(f"[ERROR] Failed to poll backend process: {e}")
            code = -999 # Assign an error code

        if code is None:
            # Process still running, schedule next check
            self.monitor_after_id = self.after(500, self._monitor_process) # Check every 500ms
            return
        

        # --- Process has Terminated ---
        self.running = False
        # Wait briefly to catch any final output from reader threads
        time.sleep(0.2)

        # Determine exit reason for logging
        exit_reason = f"finished with exit code {code}"
        if self.stopped_by_user: exit_reason = "stopped by user"
        elif code == 0: exit_reason = "completed successfully (found password)"
        elif code == 1: exit_reason = "completed (password not found)"
        elif code == 2: exit_reason = "exited with argument error"
        elif code == 3: exit_reason = "exited (7z dependency missing)"
        elif code == 4: exit_reason = "exited (path error)"
        elif code < 0: exit_reason = f"terminated abnormally (signal/error {code})" # Or use signal module on Linux/macOS

        self.update_status(f"--- Backend process {exit_reason} ---")

        # Show final result popup only if not manually stopped by user
        if not self.stopped_by_user:
            self.show_final_result_popup(code)

        # Cleanup
        self.process = None
        # Threads should exit automatically as streams close, but join defensively
        if self.stdout_thread and self.stdout_thread.is_alive(): self.stdout_thread.join(timeout=0.1)
        if self.stderr_thread and self.stderr_thread.is_alive(): self.stderr_thread.join(timeout=0.1)
        self.stdout_thread = None; self.stderr_thread = None
        self.monitor_after_id = None # Clear scheduled task ID
        self.stopped_by_user = False # Reset flag
        self.set_ui_state(True) # Re-enable UI controls
        self.save_log_to_file()  # Save log when process finishes


    def show_final_result_popup(self, code):
        """ Displays appropriate message box based on C++ exit code """
        title, msg = "Process Finished", "Password not found in the specified range."
        icon = messagebox.INFO

        if code == 0 and self.found_password:
            title, msg = "Success!", f"Password Found:\n\n{self.found_password}"
        elif code == 1:
            pass # Keep default "Not Found" message
        elif code == 2:
            title, msg, icon = "Argument Error", "Backend reported invalid arguments.\nCheck inputs & log.", messagebox.ERROR
        elif code == 3:
            title, msg, icon = "Dependency Error", "Backend Error: 7z executable not found.\nEnsure 7z.exe/7z.dll are in the root 'bin' folder.", messagebox.ERROR
        elif code == 4:
            title, msg, icon = "Path Error", "Backend Error: Could not determine its own directory or 7z path.\nCheck installation.", messagebox.ERROR
        else: # Includes negative codes (signals) or other unexpected codes
            title, msg, icon = "Runtime Error", f"Backend process exited unexpectedly (code {code}).\nCheck log for details.", messagebox.ERROR

        # Use safe_update as this might be called from the monitor thread via 'after'
        safe_update(messagebox.showinfo if icon == messagebox.INFO else messagebox.showerror, title, msg)


    def stop_cracking(self):
        """Attempts to gracefully stop the backend process by creating a stop flag,
           waiting for a period, and then forcing termination if necessary."""

        if not self.running or not self.process:
            self.update_status("Nothing to stop (backend not running or process object missing).")
            return
        if self.process.poll() is not None:
            # Process already finished, perhaps between the check and the stop button press.
            # The _monitor_process loop should handle the cleanup.
            self.update_status("Backend process already terminated.")
            # Ensure UI is consistent if monitor hasn't caught up yet
            if self.running:
                 self.running = False
                 self.set_ui_state(True)
            return

        self.update_status(">>> Initiating stop sequence...")
        self.stopped_by_user = True  # Set flag immediately

        # --- Create stop flag file ONLY if skip list feature is enabled in GUI ---
        stop_flag_path = ""
        # Check if skip list checkbox is ticked AND the global path is set
        if self.skip_var.get() and SKIP_LIST_PATH:
             stop_flag_path = SKIP_LIST_PATH + ".stop"
             try:
                 # Create an empty file to signal stop
                 with open(stop_flag_path, 'w') as f:
                     pass
                 self.update_status(f">>> Stop flag file created ({os.path.basename(stop_flag_path)}), waiting for graceful backend exit...")
             except Exception as e:
                 self.update_status(f"[ERROR] Could not create stop flag file '{stop_flag_path}': {e}")
                 stop_flag_path = "" # Ensure we don't try to remove it later if creation failed
                 # Proceed to wait/terminate anyway, but backend won't save via flag
                 self.update_status(">>> Proceeding without stop flag due to creation error.")
        else:
            self.update_status(">>> Skip list/stop flag feature not enabled. Attempting direct termination...")
            # No stop flag to create, will rely on terminate/kill below

        # --- Wait for the process to exit gracefully, with an increased timeout ---
        start_time = time.time()
        graceful_exit_timeout = 8.0 # Increased timeout in seconds (e.g., 8 seconds)
        terminated_gracefully = False

        while True: # Loop until process exits or timeout occurs
            if self.process.poll() is not None:
                # Process exited on its own (hopefully after seeing the flag or finishing)
                terminated_gracefully = True
                self.update_status(">>> Backend process exited.")
                break # Exit the wait loop

            if time.time() - start_time > graceful_exit_timeout:
                # Timeout reached, backend didn't stop gracefully
                self.update_status(f">>> Backend did not exit within {graceful_exit_timeout}s timeout.")
                break # Exit the wait loop

            # Wait a short interval before polling again
            time.sleep(0.1)

        # --- Force termination if it didn't exit gracefully ---
        if not terminated_gracefully:
            self.update_status(">>> Forcing termination...")
            try:
                # 1. Try SIGTERM first (more graceful)
                self.process.terminate()
                self.update_status(">>> Sent SIGTERM/TerminateProcess.")
                # Wait briefly for terminate to work
                try:
                    self.process.wait(timeout=0.5)
                    self.update_status(">>> Process terminated successfully after signal.")
                    terminated_gracefully = True # It reacted to terminate
                except subprocess.TimeoutExpired:
                    # 2. If terminate didn't work, use SIGKILL (forceful)
                    self.update_status(">>> Terminate ineffective, sending SIGKILL/KillProcess...")
                    self.process.kill()
                    self.update_status(">>> Process forcefully killed.")
                except Exception as e_wait:
                    # Catch errors during the wait after terminate
                    self.update_status(f"[ERROR] Error waiting after terminate: {e_wait}")
                    # Assume kill is needed if wait failed
                    self.update_status(">>> Assuming kill needed after wait error.")
                    self.process.kill()
                    self.update_status(">>> Process forcefully killed.")

            except Exception as e_term:
                # Catch errors during terminate() or kill() itself
                self.update_status(f"[ERROR] Failed to terminate/kill process: {e_term}")

        # --- Remove the stop flag file if it was successfully created ---
        if stop_flag_path:
            try:
                if os.path.exists(stop_flag_path):
                    os.remove(stop_flag_path)
                    self.update_status(f">>> Stop flag file removed ({os.path.basename(stop_flag_path)}).")
            except Exception as e:
                # Log error but don't prevent app from continuing
                self.update_status(f"[WARN] Could not remove stop flag file '{stop_flag_path}': {e}")


        # --- IMPORTANT: Let _monitor_process handle final cleanup ---
        # The _monitor_process loop runs independently and will detect the process
        # termination (whether graceful or forced). It is responsible for:
        #   - Setting self.running = False
        #   - Re-enabling the UI (self.set_ui_state(True))
        #   - Performing the final log save (self.save_log_to_file())
        #
        # Therefore, we DO NOT call those methods directly here in stop_cracking
        # to avoid race conditions or duplicate actions. We simply ensure the
        # process is terminated and the flag is removed.

        self.update_status(">>> Stop sequence complete.")

    def on_closing(self):
        """ Handles window close event """
        if self.running and self.process and self.process.poll() is None:
            if messagebox.askyesno("Exit Confirmation", "The cracking process is still running.\nDo you want to stop it and exit?", icon='warning'):
                self.update_status(">>> Stopping backend process due to application exit...")
                self.stop_cracking()
                # Schedule the final destroy after a short delay to allow monitor loop to process termination
                self.after(700, self._destroy)
            else:
                return # User cancelled exit
        else:
            self.save_log_to_file()  # Save log before exiting
            self._destroy() # No process running, destroy immediately

    def _destroy(self):
        """ Performs final cleanup and destroys the window """
        global app_instance
        print("Destroying application window...")

        # Ensure monitor loop is cancelled
        if self.monitor_after_id:
            try: self.after_cancel(self.monitor_after_id)
            except Exception: pass
            self.monitor_after_id = None

        # Force kill if process didn't terminate gracefully earlier
        if self.process and self.process.poll() is None:
             print("Backend process still running during destroy. Attempting force kill...")
             try:
                 self.process.kill() # Sends SIGKILL / TerminateProcess(Force)
                 self.process.wait(timeout=0.5) # Wait briefly
             except Exception as e:
                 print(f"Error during final process kill: {e}")

        # Clear references
        self.process = None
        if self.stdout_thread and self.stdout_thread.is_alive(): self.stdout_thread.join(timeout=0.1)
        if self.stderr_thread and self.stderr_thread.is_alive(): self.stderr_thread.join(timeout=0.1)
        self.stdout_thread = None
        self.stderr_thread = None
        app_instance = None # Clear global instance reference

        try:
            super().destroy() # Call parent CTk destroy method
        except Exception as e:
            print(f"Error during Tk destroy: {e}")


# ──────────────────────────────────────────────────────────────────────
# main
# ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Set appearance (optional)
    # ctk.set_appearance_mode("System") # Light/Dark based on OS
    # ctk.set_default_color_theme("blue") # Or "green", "dark-blue"

    app = None # Initialize app to None
    try:
        app = ArchivePasswordCrackerApp()
        app.mainloop()
    except Exception as e:
        print(f"\n--- UNHANDLED APPLICATION EXCEPTION ---");
        print(traceback.format_exc())
        # Attempt to show a graphical error message if Tkinter is still usable
        try:
            root = tk.Tk(); root.withdraw(); messagebox.showerror("Fatal Error", f"An unexpected error occurred:\n\n{e}\n\nSee console for details."); root.destroy()
        except Exception: pass # Ignore if Tkinter itself is broken
    finally:
        # Ensure cleanup happens even if mainloop fails
        if app_instance and isinstance(app_instance, ArchivePasswordCrackerApp):
             print("Attempting final cleanup...")
             # app_instance._destroy() # Calling destroy again might cause issues if already called
        print("Application exited.")