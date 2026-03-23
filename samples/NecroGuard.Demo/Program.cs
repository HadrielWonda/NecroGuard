using NecroGuard.DependencyInjection;
using NecroGuard.Abstractions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddNecroGuard(options =>
{
    options.StrictMode = true;
    options.EnableOcr = true;
});

var app = builder.Build();

app.UseNecroGuard("/ai");

app.MapPost("/ai/process", async (INecroGuard necroGuard, IFormFile file) =>
{
    using var stream = file.OpenReadStream();
    var result = await necroGuard.ScanAsync(stream, file.ContentType);
    if (result.Status != NecroGuard.Abstractions.Models.ScanStatus.Clean)
        return Results.BadRequest(new { error = "File rejected" });
    return Results.Ok(new { message = "File processed safely" });
});

app.Run();