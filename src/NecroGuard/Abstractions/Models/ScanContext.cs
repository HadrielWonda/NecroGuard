namespace NecroGuard.Abstractions.Models;

public class ScanContext
{
    public CancellationToken CancellationToken { get; set; }
    public ScanOptions Options { get; set; } = new();
    public Dictionary<string, object> SharedData { get; set; } = new();
}