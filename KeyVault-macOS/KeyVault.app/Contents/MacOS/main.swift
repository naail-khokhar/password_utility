import Cocoa
import WebKit

class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var webView: WKWebView!

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Set up the window
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1440, height: 900),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.center()
        window.title = "KeyVault"
        window.makeKeyAndOrderFront(nil)

        // Set up the WebView
        webView = WKWebView(frame: window.contentView!.bounds)
        webView.autoresizingMask = [.width, .height]
        window.contentView!.addSubview(webView)

        // Load KeyVault URL
        let url = URL(string: "https://nkhokhar.pythonanywhere.com/")!
        let request = URLRequest(url: url)
        webView.load(request)

        // Set up the menu
        let mainMenu = NSMenu()
        NSApp.mainMenu = mainMenu

        // Create the application menu
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        
        let appMenu = NSMenu()
        appMenuItem.submenu = appMenu
        appMenuItem.title = "KeyVault" // Sets the menu title explicitly
        
        // Add Quit menu item with Cmd + Q shortcut 
        let quitMenuItem = NSMenuItem(
            title: "Quit KeyVault",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        quitMenuItem.keyEquivalentModifierMask = [.command]
        appMenu.addItem(quitMenuItem)

        // Activate the app
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Optional: Add cleanup code if needed
    }
}

// Start the app
let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()