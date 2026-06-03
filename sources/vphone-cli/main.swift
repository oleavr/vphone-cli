import AppKit
import ArgumentParser
import Foundation

// Line-buffer stdout so the [frida] bridge announcements (e.g. the GDB stub
// port) are emitted promptly instead of languishing in a block buffer until the
// process exits; the kernel serial is written unbuffered via FileHandle.
setvbuf(stdout, nil, _IOLBF, 0)

do {
    let command = try VPhoneCLI.parseAsRoot()

    switch command {
    case let boot as VPhoneBootCLI:
        let app = NSApplication.shared
        let delegate = VPhoneAppDelegate(cli: boot)
        app.delegate = delegate
        app.run()

    case var patch as PatchFirmwareCLI:
        try patch.run()

    case var patch as PatchComponentCLI:
        try patch.run()

    default:
        break
    }
} catch {
    VPhoneCLI.exit(withError: error)
}
