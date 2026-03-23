namespace NecroGuard.Configuration;

public class ScannerRegistration
{
    public Type ScannerType { get; set; }
    public Dictionary<string, object> Options { get; set; } = new();
}