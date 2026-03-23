using NecroGuard.Abstractions.Models;
using NecroGuard.Scanners;
using Xunit;

namespace NecroGuard.Tests.Scanners;

public class ImageScannerTests
{
    [Fact]
    public async Task ScanAsync_WithCleanImage_ReturnsClean()
    {
        // Arrange
        var scanner = new ImageScanner();
        using var stream = File.OpenRead("testdata/clean.jpg"); // you'd need a sample file
        var context = new ScanContext { Options = new ScanOptions() };

        // Act
        var result = await scanner.ScanAsync(stream, "image/jpeg", context);

        // Assert
        Assert.Equal(ScanStatus.Clean, result.Status);
    }
}