// Lists or switches the main display's mode (public CoreGraphics API).
// Changes apply to this login session only (CGConfigureOption.forSession).
//
//   swift scripts/macos/display-mode.swift list
//   swift scripts/macos/display-mode.swift set <index>     # index from `list`
//
// Used by the Phase 2 Q4 tests to change resolution/scaling while capturing.
import CoreGraphics
import Foundation

let display = CGMainDisplayID()
let options = [kCGDisplayShowDuplicateLowResolutionModes: kCFBooleanTrue] as CFDictionary
guard let modes = CGDisplayCopyAllDisplayModes(display, options) as? [CGDisplayMode],
      let current = CGDisplayCopyDisplayMode(display) else {
    FileHandle.standardError.write("cannot read display modes\n".data(using: .utf8)!)
    exit(1)
}

func describe(_ m: CGDisplayMode) -> String {
    "\(m.width)×\(m.height) pt, \(m.pixelWidth)×\(m.pixelHeight) px, \(Int(m.refreshRate)) Hz"
}

let args = CommandLine.arguments.dropFirst()
switch args.first {
case "list":
    for (i, m) in modes.enumerated() where m.isUsableForDesktopGUI() {
        print("\(i)\t\(describe(m))\(m.ioDisplayModeID == current.ioDisplayModeID ? "\t(current)" : "")")
    }
case "set":
    guard let s = args.dropFirst().first, let i = Int(s), modes.indices.contains(i) else {
        print("usage: set <index>"); exit(2)
    }
    var config: CGDisplayConfigRef?
    guard CGBeginDisplayConfiguration(&config) == .success else { exit(1) }
    CGConfigureDisplayWithDisplayMode(config, display, modes[i], nil)
    let err = CGCompleteDisplayConfiguration(config, .forSession)
    print("from \(describe(current)) to \(describe(modes[i])): \(err == .success ? "ok" : "error \(err.rawValue)")")
    exit(err == .success ? 0 : 1)
default:
    print("usage: list | set <index>")
    exit(2)
}
