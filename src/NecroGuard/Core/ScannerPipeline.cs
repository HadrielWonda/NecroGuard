using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using System.Collections.Concurrent;

namespace NecroGuard.Core;

public class ScannerPipeline
{
    private readonly IEnumerable<IScanner> _scanners;
    private readonly ScannerPipelineOptions _options;

    public ScannerPipeline(IEnumerable<IScanner> scanners, ScannerPipelineOptions options)
    {
        _scanners = scanners;
        _options = options;
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, ScanContext context)
    {
        var applicableScanners = _scanners
            .Where(s => s.CanHandle(contentType, GetHeader(input)))
            .ToList();

        if (!applicableScanners.Any())
        {
            return new ScanResult { Status = ScanStatus.Clean };
        }

        var results = new ConcurrentBag<ScanResult>();
        var tasks = applicableScanners.Select(async scanner =>
        {
            // Create a copy of the stream for each scanner (if seekable, reset position)
            var streamCopy = await CopyStreamIfNeeded(input, context.CancellationToken);
            var result = await scanner.ScanAsync(streamCopy, contentType, context);
            results.Add(result);
        });

        await Task.WhenAll(tasks);

        // Aggregate results
        var aggregated = new ScanResult();
        bool hasMalicious = false;
        bool hasSuspicious = false;

        foreach (var r in results)
        {
            aggregated.Threats.AddRange(r.Threats);
            if (r.Status == ScanStatus.Malicious)
                hasMalicious = true;
            else if (r.Status == ScanStatus.Suspicious)
                hasSuspicious = true;
        }

        if (hasMalicious)
            aggregated.Status = ScanStatus.Malicious;
        else if (hasSuspicious && context.Options.StrictMode)
            aggregated.Status = ScanStatus.Malicious; // treat suspicious as malicious in strict mode
        else if (hasSuspicious)
            aggregated.Status = ScanStatus.Suspicious;
        else
            aggregated.Status = ScanStatus.Clean;

        return aggregated;
    }

    private byte[]? GetHeader(Stream stream)
    {
        if (!stream.CanSeek) return null;
        var pos = stream.Position;
        var buffer = new byte[256];
        var read = stream.Read(buffer, 0, buffer.Length);
        stream.Position = pos;
        return buffer[..read];
    }

    private async Task<Stream> CopyStreamIfNeeded(Stream input, CancellationToken ct)
    {
        if (input.CanSeek)
        {
            input.Position = 0;
            return input;
        }
        var ms = new MemoryStream();
        await input.CopyToAsync(ms, ct);
        ms.Position = 0;
        return ms;
    }
}