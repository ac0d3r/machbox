// Machbox Setup installs or updates the guest agent, with automatic login,
// and shows what else the guest has. The agent does the checking and leaves
// its report in checkFile; everything beyond the agent is the user's to set up.
import AppKit
import CryptoKit
import SwiftUI
import SystemConfiguration

let agentPath = "/usr/local/libexec/machbox-guest"
let agentLabel = "dev.machbox.guest"
/// agent.CheckFile. Setup does not check itself: TCC would judge Full Disk
/// Access by Setup's grant, not the agent's.
let checkFile = "/var/run/dev.machbox.guest.check.json"

struct CheckReport: Decodable {
    let agent_version: String
    let console_user: String?
    let autologin_user: String?
    let filevault: Bool
    let sip_disabled: Bool
    let features: [String]
}

enum AgentState {
    case missing, outdated, notLoaded, current

    var text: String {
        switch self {
        case .missing: return "Not installed"
        case .outdated: return "Another build is installed"
        case .notLoaded: return "Installed, not running"
        case .current: return "Installed"
        }
    }
}

/// An optional item: checked, never installed by machbox.
struct Extra: Identifiable {
    enum Action {
        case settings(String)
        case command(String, [String])
        case privileged(String, [String])
    }

    let id: String // a feature in the check report, unless done says otherwise
    let title: String
    let detail: String
    let actionTitle: String
    let action: Action
    var done: (() -> Bool)? = nil
}

/// The Mac with this VM's chip, which macOS names "<user>'s Virtual Machine".
let macName: String = {
    var size = 0
    sysctlbyname("machdep.cpu.brand_string", nil, &size, nil, 0)
    var buf = [CChar](repeating: 0, count: max(size, 1))
    sysctlbyname("machdep.cpu.brand_string", &buf, &size, nil, 0)
    let chip = String(cString: buf).replacingOccurrences(of: "(Virtual)", with: "")
        .trimmingCharacters(in: .whitespaces)
    return chip == "Apple M1" || chip == "Apple M2" ? "MacBook Air" : "MacBook Pro"
}()

/// The names macOS gives a new Mac; passed to sh as arguments, never parsed.
let rename: Extra.Action = {
    let owner = NSFullUserName().isEmpty ? NSUserName() : NSFullUserName()
    let local = String(NSUserName().map { $0.isASCII && ($0.isLetter || $0.isNumber) ? $0 : "-" })
        + "s-" + macName.replacingOccurrences(of: " ", with: "-")
    let script = "scutil --set ComputerName \"$1\" && scutil --set LocalHostName \"$2\""
    return .privileged("/bin/sh", ["-c", script, "sh", "\(owner)’s \(macName)", local])
}()

func renamed() -> Bool {
    let names = [SCDynamicStoreCopyComputerName(nil, nil) as String?, SCDynamicStoreCopyLocalHostName(nil) as String?]
    return names.allSatisfy { name in
        guard let name else { return false }
        return !name.contains("Virtual Machine") && !name.contains("Virtual-Machine")
    }
}

let extras = [
    Extra(id: "ssh", title: "Remote Login (SSH)",
          detail: "Reachable only when the VM has a network.",
          actionTitle: "Open in System Settings…",
          action: .settings("x-apple.systempreferences:com.apple.preferences.sharing?Services_RemoteLogin")),
    Extra(id: "clt", title: "Xcode Command Line Tools",
          detail: "Developer tools (otool, nm, clang…).",
          actionTitle: "Install…",
          action: .command("/usr/bin/xcode-select", ["--install"])),
    Extra(id: "rosetta", title: "Rosetta 2",
          detail: "Runs x86_64 code.",
          actionTitle: "Install…",
          action: .privileged("/usr/sbin/softwareupdate", ["--install-rosetta", "--agree-to-license"])),
    Extra(id: "rename", title: "Computer name",
          detail: "Renames “…’s Virtual Machine” to “…’s \(macName)”.",
          actionTitle: "Rename…",
          action: rename,
          done: renamed),
]

// MARK: - Processes

/// Runs a command and returns its exit status and combined output.
func run(_ path: String, _ args: [String], stdin: String? = nil) -> (Int32, String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = args
    let out = Pipe()
    process.standardOutput = out
    process.standardError = out
    let input = Pipe()
    process.standardInput = input
    do {
        try process.run()
    } catch {
        return (-1, "\(error)")
    }
    if let stdin {
        try? input.fileHandleForWriting.write(contentsOf: Data(stdin.utf8))
    }
    try? input.fileHandleForWriting.close()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (process.terminationStatus, String(decoding: data, as: UTF8.self))
}

func sha256(_ path: String) -> String? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

// MARK: - Model

/// What the password sheet is for.
enum Privileged: Identifiable {
    case install
    case command(id: String, title: String, path: String, args: [String])

    var id: String {
        switch self {
        case .install: return "install"
        case let .command(id, _, _, _): return id
        }
    }
}

@MainActor
final class Model: ObservableObject {
    @Published var report: CheckReport?
    @Published var agent: AgentState = .missing
    @Published var busy = false
    @Published var log: [String] = []
    @Published var error: String?
    @Published var asking: Privileged?

    private let resources = Bundle.main.resourceURL!

    var ready: Bool { agent == .current && !(report?.autologin_user ?? "").isEmpty }

    func done(_ extra: Extra) -> Bool {
        guard let report else { return false }
        return extra.done?() ?? report.features.contains(extra.id)
    }

    func refresh() {
        let bundled = resources.appendingPathComponent("machbox-guest").path
        DispatchQueue.global().async {
            let state = Self.agentState(bundled: bundled)
            // Only this build is sure to write the report, and only while it
            // runs; /var/run starts empty at boot.
            var report: CheckReport?
            if state == .current, let data = FileManager.default.contents(atPath: checkFile) {
                report = try? JSONDecoder().decode(CheckReport.self, from: data)
            }
            DispatchQueue.main.async {
                self.agent = state
                self.report = report
                if report == nil && state == .current {
                    self.error = Self.noCheck
                } else if self.error == Self.noCheck {
                    self.error = nil
                }
            }
        }
    }

    private static let noCheck = "Waiting for the agent's check."

    nonisolated static func agentState(bundled: String) -> AgentState {
        guard let have = sha256(agentPath) else { return .missing }
        if have != sha256(bundled) {
            return .outdated
        }
        // launchctl print of a system service may need root; pgrep does not.
        if run("/usr/bin/pgrep", ["-x", "machbox-guest"]).0 != 0 {
            return .notLoaded
        }
        return .current
    }

    func perform(_ extra: Extra) {
        switch extra.action {
        case let .settings(link):
            if let url = URL(string: link) {
                NSWorkspace.shared.open(url)
            }
        case let .command(path, args):
            DispatchQueue.global().async { _ = run(path, args) }
        case let .privileged(path, args):
            asking = .command(id: extra.id, title: "Install \(extra.title)", path: path, args: args)
        }
    }

    /// Opens the Full Disk Access pane with the agent selected in the Finder,
    /// to drag into it; its path is copied too, for + then ⌘⇧G.
    func grantFullDiskAccess() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(agentPath, forType: .string)
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: agentPath)])
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }

    /// A running process gets a new Full Disk Access grant only once restarted.
    func restartAgent() {
        asking = .command(id: "restart", title: "Restart the Machbox agent",
                          path: "/bin/launchctl", args: ["kickstart", "-k", "system/\(agentLabel)"])
    }

    /// Runs what the password sheet was for; calls back with an error to show
    /// in the sheet, or nil once it is done.
    func authorize(_ what: Privileged, password: String, done: @escaping (String?) -> Void) {
        let user = report?.console_user ?? NSUserName()
        busy = true
        error = nil
        let resources = resources.path
        DispatchQueue.global().async {
            // sudo checks the password, never a cached ticket (-k), before
            // anything runs; the commands below then use the fresh ticket.
            if run("/usr/bin/sudo", ["-k", "-S", "-p", "", "-v"], stdin: password + "\n").0 != 0 {
                DispatchQueue.main.async {
                    self.busy = false
                    done("Wrong password, or \(user) is not an administrator.")
                }
                return
            }
            DispatchQueue.main.async { done(nil) }
            let (status, output): (Int32, String)
            switch what {
            case .install:
                // One line for sudo, one for the script: sudo may not ask.
                (status, output) = run("/usr/bin/sudo",
                                       ["-S", "-p", "", "--", "/bin/sh", resources + "/install.sh", resources, user],
                                       stdin: password + "\n" + password + "\n")
            case let .command(_, _, path, args):
                (status, output) = run("/usr/bin/sudo", ["-S", "-p", "", "--", path] + args, stdin: password + "\n")
            }
            DispatchQueue.main.async {
                self.busy = false
                let lines = output.split(whereSeparator: \.isNewline).map(String.init)
                self.log.append(contentsOf: lines)
                if status != 0 {
                    self.error = lines.last ?? "Failed with status \(status)."
                }
                self.refresh()
            }
        }
    }
}

// MARK: - Views

struct Badge: View {
    let done: Bool
    var pending = "Not set"

    var body: some View {
        if done {
            Label("Done", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(.green)
        } else {
            Label(pending, systemImage: "circle").font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct Row<Trailing: View>: View {
    let title: String
    let detail: String
    @ViewBuilder let trailing: Trailing

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).fontWeight(.medium)
                Text(detail).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
            Spacer()
            trailing
        }
        .padding(.vertical, 3)
    }
}

struct PasswordSheet: View {
    @ObservedObject var model: Model
    let what: Privileged
    @State private var password = ""
    @State private var error: String?

    private var title: String {
        switch what {
        case .install: return model.agent == .missing ? "Install the Machbox agent" : "Update the Machbox agent"
        case let .command(_, title, _, _): return title
        }
    }

    private var note: String {
        switch what {
        case .install:
            return "Used to install the agent as root, and stored in this VM for automatic login, in recoverable form."
        case .command: return "Used to run it as root."
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.headline)
            SecureField("Password for \(model.report?.console_user ?? NSUserName())", text: $password)
                .onSubmit(submit)
            Text(note).font(.caption).foregroundStyle(.secondary)
            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Cancel") { model.asking = nil }
                    .keyboardShortcut(.cancelAction)
                Button(model.busy ? "Checking…" : "Continue", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || model.busy)
            }
        }
        .padding()
        .frame(width: 420)
    }

    private func submit() {
        guard !password.isEmpty, !model.busy else { return }
        model.authorize(what, password: password) { err in
            if let err {
                error = err
            } else {
                model.asking = nil
            }
        }
    }
}

struct ContentView: View {
    @StateObject private var model = Model()

    private var installTitle: String {
        switch model.agent {
        case .missing: return "Install Agent…"
        case .outdated: return "Update Agent…"
        // This build, but not running or without automatic login.
        case .notLoaded, .current: return "Reinstall Agent…"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 16) {
                if let r = model.report {
                    Text("User: \(r.console_user ?? "none")")
                    Text("SIP: \(r.sip_disabled ? "disabled" : "enabled")")
                    Text("FileVault: \(r.filevault ? "on" : "off")")
                }
                Spacer()
                Button("Refresh", action: model.refresh).disabled(model.busy)
            }
            .font(.caption)

            List {
                Section("Required") {
                    Row(title: "Machbox guest agent", detail: "Lets the host run tasks in this VM.") {
                        if model.agent == .current {
                            Badge(done: true)
                        } else {
                            Text(model.agent.text).font(.caption).foregroundStyle(.orange)
                        }
                    }
                    Row(title: "Automatic login",
                        detail: "Runs are headless; samples need a logged-in session. Set with the agent.") {
                        if let u = model.report?.autologin_user, !u.isEmpty {
                            Text(u).font(.caption).foregroundStyle(.green)
                        } else {
                            Badge(done: false)
                        }
                    }
                    if let report = model.report, !report.sip_disabled {
                        let granted = report.features.contains("full-disk-access")
                        Row(title: "Full Disk Access for the agent",
                            detail: "SIP is on: without it, runs cannot read their inputs. Drag machbox-guest from the Finder into the list (or + then ⌘⇧G, ⌘V), then restart the agent: it gets the grant only then.") {
                            VStack(alignment: .trailing, spacing: 4) {
                                Badge(done: granted)
                                if !granted {
                                    Button("Open in System Settings…", action: model.grantFullDiskAccess)
                                        .controlSize(.small)
                                        .disabled(model.busy)
                                    Button("Restart Agent…", action: model.restartAgent)
                                        .controlSize(.small)
                                        .disabled(model.busy)
                                }
                            }
                        }
                    }
                    if !model.ready {
                        HStack {
                            Spacer()
                            Button(installTitle) { model.asking = .install }
                                .disabled(model.busy)
                        }
                    }
                }
                Section("Optional — set these up yourself") {
                    if model.report == nil {
                        Text(model.agent == .outdated ? "Update the agent first." : "Install the agent first.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.report == nil ? [] : extras) { extra in
                        Row(title: extra.title, detail: extra.detail) {
                            VStack(alignment: .trailing, spacing: 4) {
                                Badge(done: model.done(extra))
                                if !model.done(extra) {
                                    Button(extra.actionTitle) { model.perform(extra) }
                                        .controlSize(.small)
                                        .disabled(model.busy)
                                }
                            }
                        }
                    }
                }
            }
            .frame(minHeight: 380)

            if !model.log.isEmpty {
                DisclosureGroup("Log") {
                    ScrollView {
                        Text(model.log.suffix(200).joined(separator: "\n"))
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .frame(height: 100)
                }
            }

            if let error = model.error {
                Text(error).foregroundStyle(.red).textSelection(.enabled)
            } else if model.ready {
                Text("The agent is ready. Close the VM window on the host to finish.")
                    .foregroundStyle(.green)
            }
        }
        .padding()
        .frame(minWidth: 600, minHeight: 560)
        .sheet(item: $model.asking) { PasswordSheet(model: model, what: $0) }
        .onAppear(perform: model.refresh)
        // Coming back from System Settings or an installer: show what changed.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            if !model.busy { model.refresh() }
        }
        // The agent rewrites its report at start and whenever the host asks (every 3 s).
        .onReceive(Timer.publish(every: 3, on: .main, in: .common).autoconnect()) { _ in
            if !model.busy { model.refresh() }
        }
    }
}

@main
struct MachboxSetupApp: App {
    var body: some Scene {
        WindowGroup("Machbox Setup") { ContentView() }
            .windowResizability(.contentMinSize)
    }
}
