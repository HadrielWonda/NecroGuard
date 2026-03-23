namespace NecroGuard.Abstractions.Models;

public class ScanResult
{
    public ScanStatus Status { get; set; }
    public List<ThreatInfo> Threats { get; set; } = new();
    public Stream? SanitizedStream { get; set; }
    public TimeSpan Duration { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
}