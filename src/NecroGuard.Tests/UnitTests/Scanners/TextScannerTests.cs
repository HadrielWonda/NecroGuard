using NecroGuard.Abstractions.Models;
using NecroGuard.Scanners;
using System.Text;
using Xunit;

namespace NecroGuard.Tests.Scanners;

public class TextScannerTests
{
    [Fact]
    public async Task ScanAsync_WithInvisibleCharacter_ReturnsSuspicious()
    {
        // Arrange
        var scanner = new TextScanner();
        var content = "Hello\u200BWorld";
        var stream = new MemoryStream(Encoding.UTF8.GetBytes(content));
        var context = new ScanContext { Options = new ScanOptions() };

        // Act
        var result = await scanner.ScanAsync(stream, "text/plain", context);

        // Assert
        Assert.Equal(ScanStatus.Suspicious, result.Status);
        Assert.Contains(result.Threats, t => t.ThreatType == "InvisibleCharacter");
    }
}