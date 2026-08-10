import SwiftUI
import AnomalousCore

/// Menu-bar sensor. The anti-Activity-Monitor: a quiet icon that changes
/// state only when something is actually wrong. No dock icon (LSUIElement),
/// no chat — cards and guided steps only.
///
/// The menu bar, popover, and the Home/Welcome windows are all owned by
/// `AppDelegate` (AppKit `NSStatusItem` + `NSPopover`), because SwiftUI's
/// `MenuBarExtra(.window)` mis-anchors its resizing panel. Only the `Settings`
/// scene stays here — SwiftUI's `Settings` is opened from AppKit via
/// `showSettingsWindow:` (see `AppDelegate.openSettingsWindow()`).
@main
struct AnomalousApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    private let appState = AppState.shared

    var body: some Scene {
        Settings {
            SettingsView(appState: appState)
        }
    }
}
