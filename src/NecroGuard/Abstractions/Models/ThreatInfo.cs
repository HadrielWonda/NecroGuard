namespace NecroGuard.Abstractions.Models;

public class ThreatInfo
{
    public string ScannerName { get; set; } = string.Empty;
    public string ThreatType { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public double Confidence { get; set; } // 0.0 - 1.0
    public Dictionary<string, object> Details { get; set; } = new();
}