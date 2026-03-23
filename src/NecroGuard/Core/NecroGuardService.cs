using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using NecroGuard.Core;
using Microsoft.Extensions.Options;

namespace NecroGuard;

public class NecroGuardService : INecroGuard
{
    private readonly ScannerPipeline _pipeline;
    private readonly NecroGuardOptions _options;

    public NecroGuardService(ScannerPipeline pipeline, IOptions<NecroGuardOptions> options)
    {
        _pipeline = pipeline;
        _options = options.Value;
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, 
                                            ScanOptions? options = null, CancellationToken cancellationToken = default)
    {
        options ??= new ScanOptions();
        // Merge with global options if needed
        if (_options.StrictMode) options.StrictMode = true;
        if (_options.MaxFileSize > 0) options.MaxFileSize = _options.MaxFileSize;

        // Validate size
        if (input.Length > options.MaxFileSize)
        {
            return new ScanResult
            {
                Status = ScanStatus.Malicious,
                Threats = { new ThreatInfo { ScannerName = "SizeValidator", ThreatType = "SizeLimitExceeded", Description = $"File exceeds max size {options.MaxFileSize} bytes", Confidence = 1.0 } }
            };
        }

        // Ensure stream is seekable
        if (!input.CanSeek)
        {
            var memoryStream = new MemoryStream();
            await input.CopyToAsync(memoryStream, cancellationToken);
            memoryStream.Position = 0;
            input = memoryStream;
        }

        var context = new ScanContext
        {
            CancellationToken = cancellationToken,
            Options = options
        };

        var result = await _pipeline.ScanAsync(input, contentType, context);
        
        // Apply sanitization if requested and needed
        if (options.EnableSanitization && result.Status != ScanStatus.Clean && result.SanitizedStream == null)
        {
            // The pipeline might already produce sanitized output if a sanitizer was triggered.
            // If not, we could attempt a default sanitization here (not implemented in this stub).
        }

        return result;
    }
}