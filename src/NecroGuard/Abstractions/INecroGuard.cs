using NecroGuard.Abstractions.Models;

namespace NecroGuard.Abstractions;

public interface INecroGuard
{
    Task<ScanResult> ScanAsync(Stream input, string contentType, 
                               ScanOptions? options = null, CancellationToken cancellationToken = default);
}