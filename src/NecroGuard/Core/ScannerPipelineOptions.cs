namespace NecroGuard.Core;

public class ScannerPipelineOptions
{
    public int MaxConcurrentScanners { get; set; } = 4;
    public TimeSpan ScannerTimeout { get; set; } = TimeSpan.FromSeconds(30);
}