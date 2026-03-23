using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;
using MetadataExtractor;
using ZXing;
using ZXing.QrCode;
using Tesseract;
using System.Drawing.Common;
using System.Text;
using System.Text.RegularExpressions;

namespace NecroGuard.Scanners;

public class ImageScanner : IScanner
{
    public string Name => "ImageScanner";

    private static readonly HashSet<string> SupportedTypes = new()
    {
        "image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"
    };

    public bool CanHandle(string contentType, byte[]? header)
    {
        return SupportedTypes.Contains(contentType.ToLowerInvariant());
    }

    public async Task<ScanResult> ScanAsync(Stream input, string contentType, 
                                            ScanContext context, CancellationToken cancellationToken = default)
    {
        var result = new ScanResult { Status = ScanStatus.Clean };
        var options = context.Options;

        if (input.CanSeek) input.Position = 0;

        // 1. Metadata extraction
        try
        {
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
                            ThreatType = "Metadata",
                            Description = $"Suspicious metadata: {tag.Name}={tag.Description}",
                            Confidence = 0.7
                        });
                        result.Status = ScanStatus.Suspicious;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Log but continue; could be malformed
        }

        // 2. QR Code decoding
        using var ms = new MemoryStream();
        input.Position = 0;
        await input.CopyToAsync(ms, cancellationToken);
        ms.Position = 0;
        using var image = Image.Load<Rgba32>(ms);
        var qrReader = new BarcodeReaderGeneric();
        // Convert ImageSharp image to ZXing's Bitmap (simplified; real conversion needed)
        var qrResult = qrReader.Decode(image.ToBitmap()); // This requires a conversion method
        if (qrResult != null && IsSuspiciousText(qrResult.Text))
        {
            result.Threats.Add(new ThreatInfo
            {
                ScannerName = Name,
                ThreatType = "QRCode",
                Description = "QR code contains suspicious text",
                Confidence = 0.8,
                Details = { ["Text"] = qrResult.Text }
            });
            result.Status = ScanStatus.Suspicious;
        }

        // 3. LSB steganography detection (basic entropy check)
        if (DetectLSBSteganography(image))
        {
            result.Threats.Add(new ThreatInfo
            {
                ScannerName = Name,
                ThreatType = "Steganography",
                Description = "LSB steganography detected",
                Confidence = 0.6
            });
            result.Status = ScanStatus.Suspicious;
        }

        // 4. OCR if enabled
        if (options.ScannerSpecificOptions.GetValueOrDefault("EnableOcr", false) as bool? == true)
        {
            try
            {
                input.Position = 0;
                using var ocr = new TesseractEngine(@"./tessdata", "eng", EngineMode.Default);
                using var pix = Pix.LoadFromMemory(await ms.ToArrayAsync(cancellationToken));
                using var page = ocr.Process(pix);
                var ocrText = page.GetText();
                if (IsSuspiciousText(ocrText))
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        ScannerName = Name,
                        ThreatType = "OCR",
                        Description = "OCR extracted suspicious text",
                        Confidence = 0.7,
                        Details = { ["Text"] = ocrText }
                    });
                    result.Status = ScanStatus.Suspicious;
                }
            }
            catch (Exception ex)
            {
                // Log OCR failure
            }
        }

        return result;
    }

    private bool IsSuspiciousMetadata(MetadataExtractor.Directory.Tag tag)
    {
        var value = tag.Description ?? string.Empty;
        return value.Length > 500 || ContainsCodePatterns(value);
    }

    private bool ContainsCodePatterns(string text)
    {
        return text.Contains("eval(", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("exec(", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("system(", StringComparison.OrdinalIgnoreCase);
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

    private bool DetectLSBSteganography(Image<Rgba32> image)
    {
        // Very basic LSB detection: compute entropy of LSBs; if high, may indicate hidden data
        // This is a heuristic; more sophisticated methods exist.
        const int sampleSize = 10000;
        int count = 0;
        int sum = 0;
        foreach (var pixel in image.Pixels.Take(sampleSize))
        {
            // LSB of each channel
            int lsb = (pixel.R & 1) + (pixel.G & 1) + (pixel.B & 1);
            sum += lsb;
            count++;
        }
        double average = (double)sum / count;
        // For random data, average LSB per pixel should be 1.5 (since three channels, each bit has 0.5 probability)
        // If average is close to 1.5, it's suspicious.
        return Math.Abs(average - 1.5) < 0.2;
    }

    // Helper to convert ImageSharp image to ZXing's Bitmap (simplified)
    private static System.Drawing.Bitmap ToBitmap(Image<Rgba32> image)
    {
        var bitmap = new System.Drawing.Bitmap(image.Width, image.Height);
        for (int y = 0; y < image.Height; y++)
        {
            for (int x = 0; x < image.Width; x++)
            {
                var pixel = image[x, y];
                bitmap.SetPixel(x, y, System.Drawing.Color.FromArgb(pixel.A, pixel.R, pixel.G, pixel.B));
            }
        }
        return bitmap;
    }
}