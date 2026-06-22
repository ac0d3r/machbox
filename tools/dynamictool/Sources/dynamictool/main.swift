import Foundation

func run() throws {
    let command: Command = try CLI.parse(Array(CommandLine.arguments.dropFirst()))

    switch command {
    case .run(let cfg):
        try runAnalysis(cfg: cfg)
    }
}

private func runAnalysis(cfg: RunConfig) throws {
    let executablePath = URL(fileURLWithPath: cfg.executable).standardizedFileURL.path

    let writer = try JSONLWriter(path: cfg.outputPath)
    defer { try? writer.close() }

    let pipeline = EventPipeline(writer: writer)
    defer { try? pipeline.flushAndClose() }

    let dtraceClient = cfg.dtraceScript.flatMap {
        DTraceClient.maybeStart(scriptPath: $0, sink: pipeline.accept)
    }
    defer { dtraceClient?.stop() }

    let esClient = EndpointSecurityClient { event in
        pipeline.accept(event)
    }
    try esClient.start()
    defer { esClient.stop() }

    var sample: LaunchedSample?

    signal(SIGTERM, SIG_IGN)
    let sigSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .global())
    sigSource.setEventHandler { [esClient, pipeline, dtraceClient] in
        esClient.stop()
        dtraceClient?.stop()
        try? pipeline.flushAndClose()
        if let s = sample {
            kill(s.pid, SIGTERM)
        }
    }
    sigSource.resume()
    defer { sigSource.cancel() }

    sample = try SampleLauncher.launch(
        executable: executablePath,
        arguments: cfg.arguments,
    )

    pipeline.accept(
        Event(
            ts: Date(),
            type: "machbox_launch",
            pid: sample!.pid,
            ppid: nil,
            process: nil,
            target: sample!.processPath,
            object: nil,
            metadata: [
                "is_child": String(sample!.isChildProcess)
            ]
        ))

    FileHandle.standardError.write(
        Data(
            "dynamictool: launched pid \(sample!.pid)\n"
                .utf8))

    if sample!.isChildProcess {
        var status: Int32 = 0
        let waitResult = waitpid(sample!.pid, &status, 0)
        guard waitResult == sample!.pid else {
            let message = String(cString: strerror(errno))
            throw AnalyzerError.launch("waitpid failed: \(message)")
        }

        FileHandle.standardError.write(
            Data("dynamictool: sample exited with status \(status)\n".utf8))
    } else {
        var buffer = [CChar](repeating: 0, count: 4096)
        while proc_pidpath(sample!.pid, &buffer, UInt32(buffer.count)) > 0 {
            Thread.sleep(forTimeInterval: 0.1)
        }
        FileHandle.standardError.write(
            Data("dynamictool: sample exited\n".utf8))
    }

    Thread.sleep(forTimeInterval: 3.0)
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
