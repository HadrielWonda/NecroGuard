namespace NecroGuard.Abstractions.Models;

public class ScanOptions
{
    public bool StrictMode { get; set; } = false;
    public bool EnableSanitization { get; set; } = true;
    public long MaxFileSize { get; set; } = 10 * 1024 * 1024; // 10 MB
    public Dictionary<string, object> ScannerSpecificOptions { get; set; } = new();
}