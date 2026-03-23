using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using MetadataExtractor;

namespace NecroGuard.Scanners;

public class MetadataScanner : IScanner
{
    public string Name => "MetadataScanner";

    public bool CanHandle(string contentType, byte[]? header)
    {
        // This scanner can run on any file type as a fallback
        return true;
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, 
                                            ScanContext context, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult { Status = ScanStatus.Clean };

        // Use MetadataExtractor to get all metadata directories
        try
        {
            if (input.CanSeek) input.Position = 0;
            var directories = ImageMetadataReader.ReadMetadata(input);
            foreach (var dir in directories)
            {
                foreach (var tag in dir.Tags)
                {
                    if (IsSuspiciousMetadata(tag))
                    {
                        result.Threats.Add(new ThreatInfo
                        {
                            ScannerName = Name,
                            ThreatType = "SuspiciousMetadata",
                            Description = $"Suspicious metadata: {tag.Name} = {tag.Description}",
                            Confidence = 0.7
                        });
                        result.Status = ScanStatus.Suspicious;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Ignore parse errors
        }

        return result;
    }

    private bool IsSuspiciousMetadata(MetadataExtractor.Directory.Tag tag)
    {
        var value = tag.Description ?? string.Empty;
        // Check for code-like strings or excessive length
        if (value.Length > 500) return true;
        if (value.Contains("eval(") || value.Contains("exec(") || value.Contains("system(")) return true;
        return false;
    }
}