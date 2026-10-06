import AppKit
import Darwin
import Foundation

struct LaunchedSample {
    let pid: pid_t
    let processPath: String
    let isChildProcess: Bool
}

enum SampleLauncher {
    static func launch(
        executable: String,
        arguments: [String]
    ) throws -> LaunchedSample {
        let url = URL(fileURLWithPath: executable).standardizedFileURL
        if url.pathExtension.lowercased() == "app" {
            return try launchApplication(
                bundleURL: url,
                arguments: arguments
            )
        }

        return try launchExecutable(url: url, arguments: arguments)
    }

    private static func launchExecutable(url: URL, arguments: [String]) throws -> LaunchedSample {
        let resolvedExecutable = url.path
        guard FileManager.default.isExecutableFile(atPath: resolvedExecutable) else {
            throw AnalyzerError.launch("sample is not executable: \(resolvedExecutable)")
        }

        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        let devNullFD = open("/dev/null", O_WRONLY)
        guard devNullFD >= 0 else {
            throw AnalyzerError.launch("failed to open /dev/null")
        }
        defer { close(devNullFD) }

        posix_spawn_file_actions_adddup2(&fileActions, devNullFD, STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&fileActions, devNullFD, STDERR_FILENO)

        var argvStorage = ([resolvedExecutable] + arguments).map { strdup($0) }
        defer {
            for pointer in argvStorage {
                free(pointer)
            }
        }
        argvStorage.append(nil)

        var pid: pid_t = 0
        let result = posix_spawn(&pid, resolvedExecutable, &fileActions, nil, argvStorage, environ)
        guard result == 0 else {
            let message = String(cString: strerror(result))
            throw AnalyzerError.launch("posix_spawn failed: \(message)")
        }

        return LaunchedSample(pid: pid, processPath: resolvedExecutable, isChildProcess: true)
    }

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
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.arguments = arguments
        configuration.activates = false
        configuration.createsNewApplicationInstance = true

        let semaphore = DispatchSemaphore(value: 0)
        var launchError: Error?

        NSWorkspace.shared.openApplication(at: bundleURL, configuration: configuration) {
            _, error in
            launchError = error
            semaphore.signal()
        }

        guard semaphore.wait(timeout: .now() + 10) == .success else {
            throw AnalyzerError.launch("LaunchServices timed out for \(bundleURL.path)")
        }

        if let launchError {
            throw AnalyzerError.launch(
                "LaunchServices failed for \(bundleURL.path): \(launchError.localizedDescription)")
        }

        // openApplication returns before the app finishes exec-ing (it launches
        // via xpcproxy).  In headless VMs NSWorkspace.runningApplications is
        // unreliable, so resolve the real PID by scanning the process table.
        let deadline = Date().addingTimeInterval(3.0)
        var resolvedPID: pid_t = 0
        while Date() < deadline {
            if let pid = findPIDByExecutablePath(processPath) {
                resolvedPID = pid
                break
            }
            Thread.sleep(forTimeInterval: 0.05)
        }

        guard resolvedPID > 0 else {
            throw AnalyzerError.launch(
                "could not resolve running application pid for \(bundleURL.path)")
        }

        return LaunchedSample(
            pid: resolvedPID,
            processPath: processPath,
            isChildProcess: false
        )
    }

    private static func findPIDByExecutablePath(_ path: String) -> pid_t? {
        // proc_listallpids(nil, 0) returns the number of pids, not bytes.
        let pidCountHint = Int(proc_listallpids(nil, 0))
        guard pidCountHint > 0 else { return nil }

        // Add headroom for processes spawned between the size query and list call.
        var pids = [pid_t](repeating: 0, count: pidCountHint + 64)
        let returnedSize = proc_listallpids(
            &pids, Int32(pids.count * MemoryLayout<pid_t>.size))
        guard returnedSize > 0 else { return nil }

        let pidCount = Int(returnedSize) / MemoryLayout<pid_t>.size
        var pathBuffer = [CChar](repeating: 0, count: 4096)
        var candidates: [pid_t] = []
        for i in 0..<pidCount {
            let pid = pids[i]
            guard pid > 0 else { continue }
            if proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count)) > 0 {
                let pidPath = String(cString: pathBuffer)
                if pidPath == path || pidPath.hasSuffix(path) {
                    candidates.append(pid)
                }
            }
        }

        // Prefer the smallest PID: the parent app process always has a lower PID
        // than any child it forks.  This avoids returning a helper/child process.
        let result = candidates.min()
        FileHandle.standardError.write(
            Data(
                "dynamictool: findPIDByExecutablePath target=\(path) scanned=\(pidCount) candidates=\(candidates) selected=\(result.map(String.init) ?? "nil")\n"
                    .utf8))
        return result
    }

}
