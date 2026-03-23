using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using System.Text;
using System.Text.RegularExpressions;

namespace NecroGuard.Sanitizers;

public class TextSanitizer : ISanitizer
{
    public string Name => "TextSanitizer";

    public bool CanHandle(ScanResult scanResult)
    {
        return scanResult.Threats.Any(t => t.ScannerName == "TextScanner");
    }

    public async Task<Stream> SanitizeAsync(Stream input, ScanResult result, CancellationToken cancellationToken = default)
    {
        string text;
        using (var reader = new StreamReader(input, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true))
        {
            text = await reader.ReadToEndAsync(cancellationToken);
        }

        // Remove invisible characters
        var cleaned = text
            .Replace("\u200B", "") // zero-width space
            .Replace("\u200C", "") // zero-width non-joiner
            .Replace("\u200D", "") // zero-width joiner
            .Replace("\uFEFF", "") // zero-width no-break space
            .Replace("\u202E", ""); // right-to-left override

        // Normalize homoglyphs (simplified)
        var homoglyphs = new Dictionary<char, char>
        {
            { 'а', 'a' }, { 'е', 'e' }, { 'о', 'o' }, { 'р', 'p' }, { 'с', 'c' }, { 'х', 'x' }
        };
        var sb = new StringBuilder();
        foreach (var ch in cleaned)
        {
            if (homoglyphs.TryGetValue(ch, out var ascii))
                sb.Append(ascii);
            else
                sb.Append(ch);
        }
        cleaned = sb.ToString();

        var outputStream = new MemoryStream(Encoding.UTF8.GetBytes(cleaned));
        return outputStream;
    }
}