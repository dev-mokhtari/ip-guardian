import AppKit
import SwiftUI

@MainActor
final class IPGuardianAppDelegate: NSObject, NSApplicationDelegate {
    /// Set the moment the user declines to quit, and cleared as soon as a
    /// window is on screen again.
    ///
    /// Dismissing the alert closes a window too, and with the main window
    /// already gone that reads to macOS as "the last window closed" — which
    /// asked the very question the user just answered, without end. The flag
    /// covers only that instant. Reopening the window clears it, so the next
    /// close is a new question and gets asked.
    private var declinedQuitWithWindowClosed = false
    private var windowObserver: NSObjectProtocol?

    func applicationDidFinishLaunching(_: Notification) {
        windowObserver = NotificationCenter.default.addObserver(
            forName: NSWindow.didBecomeMainNotification,
            object: nil,
            queue: .main
        ) { _ in
            Task { @MainActor [weak self] in
                self?.declinedQuitWithWindowClosed = false
            }
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_: NSApplication) -> Bool {
        !declinedQuitWithWindowClosed
    }

    /// Quitting cancels Protection and lets protected applications carry on
    /// unprotected, and closing the window asks macOS to quit. That is far too
    /// easy to hit by accident for something with that consequence.
    func applicationShouldTerminate(_: NSApplication) -> NSApplication.TerminateReply {
        guard GuardianController.shared.isProtectionActive else { return .terminateNow }

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Quit IP Guardian and stop Protection?"
        alert.informativeText = """
            Protection is active. Quitting cancels it, clears the trusted \
            connection, and lets protected applications keep running on \
            whichever connection is active. Cancel keeps IP Guardian watching \
            from the menu bar.
            """
        alert.addButton(withTitle: "Quit and Stop Protection")
        alert.addButton(withTitle: "Cancel")
        // Return picks Cancel: an accidental close followed by a reflexive
        // Return must never be the thing that ends Protection.
        alert.buttons[0].keyEquivalent = ""
        alert.buttons[1].keyEquivalent = "\r"

        guard alert.runModal() == .alertFirstButtonReturn else {
            declinedQuitWithWindowClosed = true
            return .terminateCancel
        }
        return .terminateNow
    }

    func applicationWillTerminate(_: Notification) {
        if let windowObserver {
            NotificationCenter.default.removeObserver(windowObserver)
        }
        GuardianController.shared.prepareForTermination()
    }
}

@main
@MainActor
struct IPGuardianApp: App {
    @NSApplicationDelegateAdaptor(IPGuardianAppDelegate.self) private var appDelegate
    @StateObject private var controller = GuardianController.shared

    var body: some Scene {
        Window("IP Guardian", id: "main") {
            MainWindowView(controller: controller)
                .frame(minWidth: 960, minHeight: 660)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1080, height: 720)

        MenuBarExtra {
            MenuContentView(controller: controller)
        } label: {
            Image(systemName: controller.mode.symbolName)
                .accessibilityLabel("IP Guardian: \(controller.mode.title)")
        }
        .menuBarExtraStyle(.window)
    }
}
