using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using System.IO.Compression;
using SharpCompress.Archives;
using SharpCompress.Readers;

namespace NecroGuard.Scanners;

public class OfficeScanner : IScanner
{
    public string Name => "OfficeScanner";

    private static readonly HashSet<string> SupportedTypes = new()
    {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint"
    };

    public bool CanHandle(string contentType, byte[]? header)
    {
        return SupportedTypes.Contains(contentType.ToLowerInvariant()) ||
               (header != null && header.Length >= 2 && header[0] == 0xD0 && header[1] == 0xCF); // legacy OLE
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, 
                                            ScanContext context, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult { Status = ScanStatus.Clean };

        if (input.CanSeek) input.Position = 0;

        // Check for macros in OLE structured storage (legacy)
        if (contentType == "application/msword" || contentType == "application/vnd.ms-excel" || contentType == "application/vnd.ms-powerpoint")
        {
            // Use SharpCompress to inspect OLE streams
            try
            {
                using var archive = ArchiveFactory.Open(input);
                foreach (var entry in archive.Entries)
                {
                    if (entry.Key?.Contains("Macro", StringComparison.OrdinalIgnoreCase) == true ||
                        entry.Key?.Contains("VBA", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        result.Threats.Add(new ThreatInfo
                        {
                            ScannerName = Name,
                            ThreatType = "Macro",
                            Description = $"Macro detected: {entry.Key}",
                            Confidence = 0.9
                        });
                        result.Status = ScanStatus.Malicious;
                    }
                }
            }
            catch (Exception ex)
            {
                // Possibly corrupted or encrypted
            }
        }
        else if (contentType.StartsWith("application/vnd.openxmlformats-officedocument"))
        {
            // Open XML format
            using var doc = WordprocessingDocument.Open(input, false);
            if (doc != null)
            {
                // Check for VBA project (macros)
                if (doc.VbaProjectPart != null)
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        ScannerName = Name,
                        ThreatType = "Macro",
                        Description = "VBA project (macro) detected in Open XML document",
                        Confidence = 0.9
                    });
                    result.Status = ScanStatus.Malicious;
                }

                // Extract and scan text
                var text = ExtractTextFromOpenXml(doc);
                if (IsSuspiciousText(text))
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        ScannerName = Name,
                        ThreatType = "Text",
                        Description = "Suspicious text in document",
                        Confidence = 0.7
                    });
                    result.Status = ScanStatus.Suspicious;
                }

                // Check for hidden text
                var body = doc.MainDocumentPart?.Document.Body;
                if (body != null)
                {
                    var hiddenElements = body.Descendants<Run>().Where(r => r.RunProperties?.Hidden?.Val?.Value == true);
                    if (hiddenElements.Any())
                    {
                        result.Threats.Add(new ThreatInfo
                        {
                            ScannerName = Name,
                            ThreatType = "HiddenText",
                            Description = "Hidden text detected",
                            Confidence = 0.6
                        });
                        result.Status = ScanStatus.Suspicious;
                    }
                }
            }
        }

        return result;
    }

    private string ExtractTextFromOpenXml(WordprocessingDocument doc)
    {
        var text = string.Empty;
        if (doc.MainDocumentPart != null)
        {
            text = doc.MainDocumentPart.Document.Body.InnerText;
        }
        return text;
    }

    private bool IsSuspiciousText(string text)
    {
        return text.Contains("ignore previous instructions", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("system prompt", StringComparison.OrdinalIgnoreCase);
    }
}