using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

namespace NecroGuard.Sanitizers;

public class ImageSanitizer : ISanitizer
{
    public string Name => "ImageSanitizer";

    public bool CanHandle(ScanResult scanResult)
    {
        return scanResult.Threats.Any(t => t.ScannerName == "ImageScanner");
    }

    public async Task<Stream> SanitizeAsync(Stream input, ScanResult result, CancellationToken cancellationToken = default)
    {
        if (input.CanSeek) input.Position = 0;
        using var image = await Image.LoadAsync<Rgba32>(input, cancellationToken);
        // Remove metadata by re-encoding without preserving metadata
        var outputStream = new MemoryStream();
        await image.SaveAsync(outputStream, image.Metadata.DecodedImageFormat ?? SixLabors.ImageSharp.Formats.Png.PngFormat.Instance, cancellationToken);
        outputStream.Position = 0;
        return outputStream;
    }
}