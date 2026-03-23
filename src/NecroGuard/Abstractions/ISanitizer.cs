using NecroGuard.Abstractions.Models;

namespace NecroGuard.Abstractions;

public interface ISanitizer
{
    string Name { get; }
    bool CanHandle(ScanResult scanResult);
    Task<Stream> SanitizeAsync(Stream input, ScanResult result, 
                               CancellationToken cancellationToken = default);
}