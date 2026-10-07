import AppKit
import Darwin
import Foundation

struct LaunchedSample {
    let pid: pid_t
    let processPath: String
    /// True when the sample is a direct `posix_spawn` child (waitpid-able).
    let isChildProcess: Bool
}

enum SampleLauncher {
    private static let launchServicesTimeout: TimeInterval = 10
    private static let pidResolveTimeout: TimeInterval = 3
    private static let pidPollInterval: TimeInterval = 0.05

    static func launch(
        executable: String,
        arguments: [String]
    ) throws -> LaunchedSample {
        let url = URL(fileURLWithPath: executable).standardizedFileURL
        if url.pathExtension.lowercased() == "app" {
            return try launchApplication(bundleURL: url, arguments: arguments)
        }
        return try launchExecutable(url: url, arguments: arguments)
    }

    /// Mach-O path used for ES path muting (bundle → executable, else the path itself).
    static func executablePath(for samplePath: String) -> String {
        let url = URL(fileURLWithPath: samplePath).standardizedFileURL
        if url.pathExtension.lowercased() == "app",
            let executable = Bundle(url: url)?.executableURL?.path
        {
            return executable
        }
        return url.path
    }

    // MARK: - Mach-O / script

    private static func launchExecutable(url: URL, arguments: [String]) throws -> LaunchedSample {
        let resolvedExecutable = url.path
        guard FileManager.default.isExecutableFile(atPath: resolvedExecutable) else {
            throw AnalyzerError.launch("sample is not executable: \(resolvedExecutable)")
        }

        var fileActions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&fileActions) == 0 else {
            throw AnalyzerError.launch("posix_spawn_file_actions_init failed")
        }
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        let devNullFD = open("/dev/null", O_RDWR)
        guard devNullFD >= 0 else {
            throw AnalyzerError.launch("failed to open /dev/null")
        }
        defer { close(devNullFD) }

        guard
            posix_spawn_file_actions_adddup2(&fileActions, devNullFD, STDIN_FILENO) == 0,
            posix_spawn_file_actions_adddup2(&fileActions, devNullFD, STDOUT_FILENO) == 0,
            posix_spawn_file_actions_adddup2(&fileActions, devNullFD, STDERR_FILENO) == 0
        else {
            throw AnalyzerError.launch("posix_spawn_file_actions_adddup2 failed")
        }

        var argvStorage = ([resolvedExecutable] + arguments).map { strdup($0) }
        defer {
            for pointer in argvStorage {
                free(pointer)
            }
        }
        argvStorage.append(nil)

        var pid: pid_t = 0
        let result = posix_spawn(
            &pid, resolvedExecutable, &fileActions, nil, argvStorage, environ)
        guard result == 0 else {
            throw AnalyzerError.launch(
                "posix_spawn failed: \(String(cString: strerror(result)))")
        }

        return LaunchedSample(
            pid: pid, processPath: resolvedExecutable, isChildProcess: true)
    }

    // MARK: - .app bundle

    private static func launchApplication(
        bundleURL: URL,
        arguments: [String]
    ) throws -> LaunchedSample {
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath: bundleURL.path, isDirectory: &isDirectory),
            isDirectory.boolValue
        else {
            throw AnalyzerError.launch("app bundle does not exist: \(bundleURL.path)")
        }

        guard let executableURL = Bundle(url: bundleURL)?.executableURL else {
            throw AnalyzerError.launch("app bundle has no executable: \(bundleURL.path)")
        }
        let processPath = executableURL.path

        // Ignore pre-existing instances of the same binary (common in reused VMs).
        let preexisting = pids(matchingExecutable: processPath)

        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = arguments
        configuration.activates = false
        configuration.createsNewApplicationInstance = true

        let runningApp = try openApplication(
            at: bundleURL, configuration: configuration)

        if let pid = validatedPID(from: runningApp, expectedPath: processPath),
            !preexisting.contains(pid)
        {
            logPIDResolution(
                path: processPath, selected: pid, source: "NSRunningApplication",
                candidates: [pid])
            return LaunchedSample(
                pid: pid, processPath: processPath, isChildProcess: false)
        }

        // openApplication often returns before exec (via xpcproxy). Headless VMs
        // also make NSWorkspace.runningApplications unreliable — poll the table.
        let deadline = Date().addingTimeInterval(pidResolveTimeout)
        var selected: pid_t?
        var lastCandidates: [pid_t] = []
        while Date() < deadline {
            let candidates = pids(matchingExecutable: processPath)
                .subtracting(preexisting)
                .sorted()
            lastCandidates = candidates
            // Lowest new PID is typically the main app (helpers fork later).
            if let pid = candidates.first {
                selected = pid
                break
            }
            Thread.sleep(forTimeInterval: pidPollInterval)
        }

        guard let resolvedPID = selected else {
            throw AnalyzerError.launch(
                "could not resolve running application pid for \(bundleURL.path)")
        }

        logPIDResolution(
            path: processPath, selected: resolvedPID, source: "proc_listallpids",
            candidates: lastCandidates)
        return LaunchedSample(
            pid: resolvedPID, processPath: processPath, isChildProcess: false)
    }

    private static func openApplication(
        at bundleURL: URL,
        configuration: NSWorkspace.OpenConfiguration
    ) throws -> NSRunningApplication? {
        let semaphore = DispatchSemaphore(value: 0)
        var launchError: Error?
        var runningApp: NSRunningApplication?

        NSWorkspace.shared.openApplication(at: bundleURL, configuration: configuration) {
            app, error in
            runningApp = app
            launchError = error
            semaphore.signal()
        }

        guard semaphore.wait(timeout: .now() + launchServicesTimeout) == .success else {
            throw AnalyzerError.launch("LaunchServices timed out for \(bundleURL.path)")
        }
        if let launchError {
            throw AnalyzerError.launch(
                "LaunchServices failed for \(bundleURL.path): \(launchError.localizedDescription)")
        }
        return runningApp
    }

    private static func validatedPID(
        from app: NSRunningApplication?,
        expectedPath: String
    ) -> pid_t? {
        guard let app else { return nil }
        let pid = app.processIdentifier
        guard pid > 0 else { return nil }
        guard let path = processPath(for: pid),
            PathNormalization.matches(path, expectedPath)
        else {
            return nil
        }
        return pid
    }

    // MARK: - Process table

    private static func pids(matchingExecutable path: String) -> Set<pid_t> {
        guard let all = listAllPIDs() else { return [] }
        var matches = Set<pid_t>()
        for pid in all where pid > 0 {
            guard let pidPath = processPath(for: pid),
                PathNormalization.matches(pidPath, path)
            else {
                continue
            }
            matches.insert(pid)
        }
        return matches
    }

    private static func listAllPIDs() -> [pid_t]? {
        // proc_listallpids(nil, 0) returns the number of pids, not bytes.
        let hint = Int(proc_listallpids(nil, 0))
        guard hint > 0 else { return nil }

        var pids = [pid_t](repeating: 0, count: hint + 64)
        let returnedSize = proc_listallpids(
            &pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        guard returnedSize > 0 else { return nil }

        let count = Int(returnedSize) / MemoryLayout<pid_t>.size
        return Array(pids.prefix(count))
    }

    private static func processPath(for pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    private static func logPIDResolution(
        path: String,
        selected: pid_t,
        source: String,
        candidates: [pid_t]
    ) {
        FileHandle.standardError.write(
            Data(
                "dynamictool: resolvePID path=\(path) source=\(source) candidates=\(candidates) selected=\(selected)\n"
                    .utf8))
    }
}
