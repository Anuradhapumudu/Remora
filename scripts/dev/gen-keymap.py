#!/usr/bin/env python3
"""Generate the key tables for remote keyboard input (phase4.6-criteria L3).

The viewer turns winit's `KeyCode` (a physical key) into a USB HID usage
(the wire format, protocol.md §5); the Linux host turns the HID usage into
an evdev key code for the RemoteDesktop portal. Every NUMBER comes from a
source file that is read here, not typed from memory (CLAUDE.md "verified
vs asserted"):

  HID usages  Apple's IOHIDUsageTables.h (macOS SDK), the kHIDUsage_Keyboard*
              and kHIDUsage_Keypad* constants
  evdev codes winit 0.30.13 `scancode_to_physicalkey`
              (src/platform_impl/linux/common/xkb/keymap.rs), which maps
              evdev codes to `KeyCode`; each number is cross-checked
              against linux/input-event-codes.h by name below

Only the NAME pairing KeyCode <-> Apple constant is written by hand (the
`HID_NAME` rules), and a check fails if a paired name does not exist.

    gen-keymap.py <IOHIDUsageTables.h> <winit keymap.rs> <input-event-codes.h> <out-dir>

Writes <out-dir>/viewer_keymap.rs and <out-dir>/input_keymap.rs; copy them
to crates/remora-viewer/src/keymap.rs and crates/remora-input/src/keymap.rs.
Stdlib only.
"""

import re
import sys

# KeyCode name -> Apple constant suffix, where the rule below doesn't fit.
HID_NAME = {
    "Enter": "ReturnOrEnter", "Backspace": "DeleteOrBackspace", "Space": "Spacebar",
    "Minus": "Hyphen", "Equal": "EqualSign", "BracketLeft": "OpenBracket",
    "BracketRight": "CloseBracket", "Backquote": "GraveAccentAndTilde",
    "Delete": "DeleteForward", "ArrowRight": "RightArrow", "ArrowLeft": "LeftArrow",
    "ArrowDown": "DownArrow", "ArrowUp": "UpArrow", "IntlBackslash": "NonUSBackslash",
    "ContextMenu": "Application", "ControlLeft": "LeftControl", "ShiftLeft": "LeftShift",
    "AltLeft": "LeftAlt", "SuperLeft": "LeftGUI", "ControlRight": "RightControl",
    "ShiftRight": "RightShift", "AltRight": "RightAlt", "SuperRight": "RightGUI",
    "IntlRo": "International1", "IntlYen": "International3", "Lang1": "LANG1",
    "Lang2": "LANG2", "AudioVolumeMute": "Mute", "AudioVolumeUp": "VolumeUp",
    "AudioVolumeDown": "VolumeDown",
    "Backslash": "Backslash", "Semicolon": "Semicolon", "Quote": "Quote", "Comma": "Comma",
    "Period": "Period", "Slash": "Slash", "CapsLock": "CapsLock", "Tab": "Tab",
    "Escape": "Escape", "PrintScreen": "PrintScreen", "ScrollLock": "ScrollLock",
    "Pause": "Pause", "Insert": "Insert", "Home": "Home", "PageUp": "PageUp", "End": "End",
    "PageDown": "PageDown",
    "NumLock": "KeypadNumLock", "NumpadDivide": "KeypadSlash",
    "NumpadMultiply": "KeypadAsterisk", "NumpadSubtract": "KeypadHyphen",
    "NumpadAdd": "KeypadPlus", "NumpadEnter": "KeypadEnter", "NumpadDecimal": "KeypadPeriod",
    "NumpadEqual": "KeypadEqualSign", "NumpadComma": "KeypadComma",
}


def hid_suffix(code):
    if code in HID_NAME:
        return HID_NAME[code]
    m = re.fullmatch(r"Key([A-Z])", code)
    if m:
        return m.group(1)
    m = re.fullmatch(r"Digit(\d)", code)
    if m:
        return m.group(1)
    m = re.fullmatch(r"F(\d+)", code)
    if m:
        return code
    m = re.fullmatch(r"Numpad(\d)", code)
    if m:
        return "Keypad" + m.group(1)
    return None


def apple_hid(path):
    text = open(path, encoding="latin-1").read()
    out = {}
    for name, val in re.findall(r"kHIDUsage_(Keyboard\w*|Keypad\w*)\s*=\s*(0x[0-9A-Fa-f]+)", text):
        out[name] = int(val, 16)
    return out


def winit_evdev(path):
    text = open(path, encoding="utf-8").read()
    body = text[text.index("fn scancode_to_physicalkey"):]
    body = body[: body.index("\n}\n")]
    out = {}
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("//"):
            continue
        m = re.fullmatch(r"(\d+) => KeyCode::(\w+),", s)
        if m and m.group(2) not in out:
            out[m.group(2)] = int(m.group(1))
    return out


def evdev_names(path):
    text = open(path, encoding="utf-8").read()
    names = {}
    for name, val in re.findall(r"#define\s+(KEY_\w+)\s+(0x[0-9a-fA-F]+|\d+)\b", text):
        names.setdefault(int(val, 0), []).append(name)
    return names


def main():
    if len(sys.argv) != 5:
        print(__doc__)
        return 2
    hid = apple_hid(sys.argv[1])
    evdev = winit_evdev(sys.argv[2])
    names = evdev_names(sys.argv[3])
    rows, problems = [], []
    for code, ev in sorted(evdev.items(), key=lambda kv: kv[1]):
        suffix = hid_suffix(code)
        if suffix is None:
            continue  # no HID usage pairing written: the key is not sent
        key = suffix if suffix.startswith("Keypad") else "Keyboard" + suffix
        if key not in hid:
            problems.append(f"{code}: kHIDUsage_{key} is not in the header")
            continue
        if ev not in names:
            problems.append(f"{code}: evdev {ev} has no KEY_ name in input-event-codes.h")
            continue
        rows.append((code, hid[key], ev, names[ev][0]))
    usages = [r[1] for r in rows]
    if len(set(usages)) != len(usages):
        problems.append("two KeyCodes map to one HID usage")
    for p in problems:
        print(f"PROBLEM: {p}")
    if problems:
        return 1
    head = ("// GENERATED by scripts/dev/gen-keymap.py from Apple's IOHIDUsageTables.h,\n"
            "// winit 0.30.13's Linux keymap.rs and linux/input-event-codes.h (kernel-headers\n"
            "// 7.2.4, Fedora 44). Do not edit by hand; rerun the script.\n")
    v = [head, "\n/// USB HID usage (keyboard page) of a physical key; `None` for keys\n",
         "/// that are not sent.\n",
         "pub(crate) fn hid_usage(code: winit::keyboard::KeyCode) -> Option<u32> {\n",
         "    use winit::keyboard::KeyCode as K;\n    Some(match code {\n"]
    v += [f"        K::{c} => 0x{h:02X},\n" for c, h, _, _ in rows]
    v += ["        _ => return None,\n    })\n}\n"]
    i = [head, "\n/// The evdev key code (linux/input-event-codes.h) for a USB HID usage;\n",
         "/// `None` for usages the host does not inject (L3: dropped and counted).\n",
         "pub fn evdev_key(usb_hid_usage: u32) -> Option<u32> {\n",
         "    Some(match usb_hid_usage {\n"]
    i += [f"        0x{h:02X} => {e}, // {n}\n" for _, h, e, n in sorted(rows, key=lambda r: r[1])]
    i += ["        _ => return None,\n    })\n}\n"]
    out = sys.argv[4]
    open(f"{out}/viewer_keymap.rs", "w").write("".join(v))
    open(f"{out}/input_keymap.rs", "w").write("".join(i))
    print(f"gen-keymap: {len(rows)} keys")
    return 0


if __name__ == "__main__":
    sys.exit(main())
