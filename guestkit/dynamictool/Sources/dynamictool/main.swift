import Darwin
import Foundation

func run() throws {
    let command = try CLI.parse(Array(CommandLine.arguments.dropFirst()))
    switch command {
    case .run(let cfg):
        try runAnalysis(cfg: cfg)
    }
}

private func runAnalysis(cfg: RunConfig) throws {
    let executablePath = URL(fileURLWithPath: cfg.executable).standardizedFileURL.path

    let writer = try JSONLWriter(path: cfg.outputPath)
    let pipeline = EventPipeline(writer: writer)
    defer { try? pipeline.flushAndClose() }

    var dtraceClient: DTraceClient?
    defer { dtraceClient?.stop() }

    let esClient = EndpointSecurityClient { event in
        pipeline.accept(event)
    }
    try esClient.start()
    defer { esClient.stop() }

    var sample: LaunchedSample?

    signal(SIGTERM, SIG_IGN)
    let sigSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    sigSource.setEventHandler {
        if let s = sample {
            kill(s.pid, SIGTERM)
        }
        esClient.stop()
        dtraceClient?.stop()
        try? pipeline.flushAndClose()
        _exit(0)
    }
    sigSource.resume()
    defer { sigSource.cancel() }

    let targetPath = SampleLauncher.executablePath(for: executablePath)
    esClient.prepareTarget(path: targetPath)

    // Arm DTrace before launch. Starting after launch misses the sample's first
    // socket/connect (e.g. mDNS). TARGET_PID=0 selects the execname denylist in
    // network.d; the report later keeps only PIDs in the sample process tree.
    if let script = cfg.dtraceScript {
        dtraceClient = DTraceClient.maybeStart(
            scriptPath: script,
            targetPid: 0,
            sink: pipeline.accept
        )
    }

    let launched = try SampleLauncher.launch(
        executable: executablePath,
        arguments: cfg.arguments
    )
    sample = launched

    esClient.setTarget(pid: launched.pid, path: launched.processPath)

    pipeline.accept(
        Event(
            ts: Date(),
            type: "machbox_launch",
            pid: launched.pid,
            ppid: nil,
            process: nil,
            target: launched.processPath,
            metadata: ["is_child": String(launched.isChildProcess)]
        ))

    FileHandle.standardError.write(
        Data("dynamictool: launched pid \(launched.pid) path=\(launched.processPath)\n".utf8))

    try waitForSampleExit(launched)

    // Let late ES/DTrace events drain before teardown.
    Thread.sleep(forTimeInterval: 3.0)
}

private func waitForSampleExit(_ sample: LaunchedSample) throws {
    if sample.isChildProcess {
        var status: Int32 = 0
        let waitResult = waitpid(sample.pid, &status, 0)
        guard waitResult == sample.pid else {
            throw AnalyzerError.launch(
                "waitpid failed: \(String(cString: strerror(errno)))")
        }
        FileHandle.standardError.write(
            Data("dynamictool: sample exited status=\(describeWaitStatus(status))\n".utf8))
        return
    }

    var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    while proc_pidpath(sample.pid, &buffer, UInt32(buffer.count)) > 0 {
        Thread.sleep(forTimeInterval: 0.1)
    }
    FileHandle.standardError.write(Data("dynamictool: sample exited\n".utf8))
}

private func describeWaitStatus(_ status: Int32) -> String {
    // Swift can't import wait(2) status macros; decode the Darwin layout directly.
    if (status & 0x7f) == 0 {
        return "exit(\((status >> 8) & 0xff))"
    }
    if (status & 0xff) != 0x7f {
        return "signal(\(status & 0x7f))"
    }
    return "raw(\(status))"
}

do {
    try run()
} catch let error as AnalyzerError {
    FileHandle.standardError.write(Data("error: \(error.description)\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
