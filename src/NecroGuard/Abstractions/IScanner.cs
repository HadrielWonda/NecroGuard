using NecroGuard.Abstractions.Models;

namespace NecroGuard.Abstractions;

public interface IScanner
{
    string Name { get; }
    bool CanHandle(string contentType, byte[]? header);
    Task<ScanResult> ScanAsync(Stream input, string contentType, 
                               ScanContext context, CancellationToken cancellationToken = default);
}