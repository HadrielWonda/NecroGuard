namespace NecroGuard.Configuration;

public class NecroGuardOptions
{
    public bool StrictMode { get; set; } = false;
    public long MaxFileSize { get; set; } = 10 * 1024 * 1024; // 10 MB
    public bool EnableOcr { get; set; } = false;
    public int MaxConcurrentScanners { get; set; } = 4;
    public TimeSpan ScannerTimeout { get; set; } = TimeSpan.FromSeconds(30);
}