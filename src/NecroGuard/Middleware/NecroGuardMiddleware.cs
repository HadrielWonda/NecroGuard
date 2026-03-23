using Microsoft.AspNetCore.Http;
using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;

namespace NecroGuard.Middleware;

public class NecroGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly INecroGuard _necroGuard;
    private readonly PathString _pathPattern;

    public NecroGuardMiddleware(RequestDelegate next, INecroGuard necroGuard, string pathPattern = "/api/ai")
    {
        _next = next;
        _necroGuard = necroGuard;
        _pathPattern = new PathString(pathPattern);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.Request.Path.StartsWithSegments(_pathPattern) &&
            (context.Request.HasFormContentType || context.Request.ContentType?.StartsWith("multipart/") == true))
        {
            // Process uploaded files
            var form = await context.Request.ReadFormAsync();
            var files = form.Files;
            foreach (var file in files)
            {
                using var stream = file.OpenReadStream();
                var result = await _necroGuard.ScanAsync(stream, file.ContentType);
                if (result.Status != ScanStatus.Clean)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("File rejected due to security concerns.");
                    return;
                }
                // Optionally replace stream with sanitized version (complex)
            }
        }
        await _next(context);
    }
}