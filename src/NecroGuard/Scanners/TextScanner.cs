using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace NecroGuard.Scanners;

public class TextScanner : IScanner
{
    public string Name => "TextScanner";

    public bool CanHandle(string contentType, byte[]? header)
    {
        return contentType.StartsWith("text/") || 
               contentType == "application/json" ||
               contentType == "application/xml";
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, 
                                            ScanContext context, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult { Status = ScanStatus.Clean };

        string text;
        using (var reader = new StreamReader(input, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true))
        {
            text = await reader.ReadToEndAsync(cancellationToken);
        }

        // 1. Detect invisible Unicode characters
        var invisibleChars = new[] { '\u200B', '\u200C', '\u200D', '\uFEFF', '\u202E' };
        var foundInvisible = false;
        foreach (var ch in invisibleChars)
        {
            if (text.Contains(ch))
            {
                foundInvisible = true;
                result.Threats.Add(new ThreatInfo
                {
                    ScannerName = Name,
                    ThreatType = "InvisibleCharacter",
                    Description = $"Invisible Unicode character U+{(int)ch:X4} detected",
                    Confidence = 0.8
                });
            }
        }
        if (foundInvisible) result.Status = ScanStatus.Suspicious;

        // 2. Homoglyph detection (simplified)
        var homoglyphs = new Dictionary<char, char>
        {
            { 'а', 'a' }, // Cyrillic a
            { 'е', 'e' },
            { 'о', 'o' },
            { 'р', 'p' },
            { 'с', 'c' },
            { 'х', 'x' }
        };
        var normalized = new StringBuilder();
        foreach (var ch in text)
        {
            if (homoglyphs.TryGetValue(ch, out var ascii))
                normalized.Append(ascii);
            else
                normalized.Append(ch);
        }
        var normalizedText = normalized.ToString();
        if (normalizedText != text)
        {
            result.Threats.Add(new ThreatInfo
            {
                ScannerName = Name,
                ThreatType = "Homoglyph",
                Description = "Text contains homoglyphs (look-alike characters)",
                Confidence = 0.6
            });
            result.Status = ScanStatus.Suspicious;
        }

        // 3. Check for encoded payloads (base64)
        var base64Pattern = @"^[A-Za-z0-9+/]+=*$";
        var words = text.Split(new[] { ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var word in words)
        {
            if (Regex.IsMatch(word, base64Pattern) && word.Length > 20)
            {
                try
                {
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(word));
                    if (IsSuspiciousText(decoded))
                    {
                        result.Threats.Add(new ThreatInfo
                        {
                            ScannerName = Name,
                            ThreatType = "Base64Payload",
                            Description = "Base64 encoded suspicious text detected",
                            Confidence = 0.8,
                            Details = { ["Decoded"] = decoded }
                        });
                        result.Status = ScanStatus.Malicious;
                    }
                }
                catch { }
            }
        }

        // 4. Pattern matching for prompt injection
        if (IsSuspiciousText(text))
        {
            result.Threats.Add(new ThreatInfo
            {
                ScannerName = Name,
                ThreatType = "PromptInjection",
                Description = "Suspicious prompt injection patterns found",
                Confidence = 0.9
            });
            result.Status = ScanStatus.Malicious;
        }

        return result;
    }

    private bool IsSuspiciousText(string text)
    {
        var patterns = new[]
        {
            @"ignore\s+previous\s+instructions",
            @"system\s+prompt",
            @"eval\s*\(",
            @"exec\s*\(",
            @"system\s*\(",
            @"cmd\.exe",
            @"powershell",
            @"<script",
            @"javascript:"
        };
        return patterns.Any(p => Regex.IsMatch(text, p, RegexOptions.IgnoreCase));
    }
}