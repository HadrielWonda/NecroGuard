using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using UglyToad.PdfPig;
using UglyToad.PdfPig.Content;

namespace NecroGuard.Scanners;

public class PdfScanner : IScanner
{
    public string Name => "PdfScanner";

    public bool CanHandle(string contentType, byte[]? header)
    {
        return contentType == "application/pdf" || 
               (header != null && header.Length >= 4 && 
                header[0] == '%' && header[1] == 'P' && header[2] == 'D' && header[3] == 'F');
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, 
                                            ScanContext context, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult { Status = ScanStatus.Clean };

        // Ensure stream is at beginning
        if (input.CanSeek) input.Position = 0;

        try
        {
            using var pdf = PdfDocument.Open(input, new ParsingOptions { SkipParsing = false });

            // Check for JavaScript
            if (pdf.Advanced?.Catalog?.Names?.JavaScript?.Any() == true)
            {
                result.Threats.Add(new ThreatInfo
                {
                    ScannerName = Name,
                    ThreatType = "JavaScript",
                    Description = "PDF contains JavaScript actions",
                    Confidence = 0.9
                });
                result.Status = ScanStatus.Malicious;
            }

            // Check for embedded files
            if (pdf.Advanced?.Catalog?.Names?.EmbeddedFiles?.Any() == true)
            {
                result.Threats.Add(new ThreatInfo
                {
                    ScannerName = Name,
                    ThreatType = "EmbeddedFile",
                    Description = "PDF contains embedded files",
                    Confidence = 0.8
                });
                result.Status = ScanStatus.Suspicious;
            }

            // Extract and analyze text
            var fullText = string.Empty;
            foreach (var page in pdf.GetPages())
            {
                var text = page.Text;
                if (IsSuspiciousText(text))
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        ScannerName = Name,
                        ThreatType = "Text",
                        Description = "Suspicious text found in PDF content",
                        Confidence = 0.7,
                        Details = { ["Page"] = page.Number, ["Text"] = text.Substring(0, Math.Min(100, text.Length)) }
                    });
                    result.Status = ScanStatus.Suspicious;
                }
                fullText += text;
            }

            // Check metadata
            if (pdf.Information != null)
            {
                var metaText = pdf.Information.Author + pdf.Information.Title + pdf.Information.Subject;
                if (IsSuspiciousText(metaText))
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        ScannerName = Name,
                        ThreatType = "Metadata",
                        Description = "Suspicious text in PDF metadata",
                        Confidence = 0.7
                    });
                    result.Status = ScanStatus.Suspicious;
                }
            }
        }
        catch (Exception ex)
        {
            // Malformed PDF could be an attack
            result.Threats.Add(new ThreatInfo
            {
                ScannerName = Name,
                ThreatType = "ParseError",
                Description = $"Failed to parse PDF: {ex.Message}",
                Confidence = 0.5
            });
            result.Status = ScanStatus.Suspicious;
        }

        return result;
    }

    private bool IsSuspiciousText(string text)
    {
        return text.Contains("ignore previous instructions", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("system prompt", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("eval(", StringComparison.OrdinalIgnoreCase);
    }
}