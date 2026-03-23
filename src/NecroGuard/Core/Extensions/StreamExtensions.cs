namespace NecroGuard.Core.Extensions;

public static class StreamExtensions
{
    public static async Task<byte[]> ReadAllBytesAsync(this Stream stream, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        await stream.CopyToAsync(ms, ct);
        return ms.ToArray();
    }
}