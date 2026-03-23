using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using NecroGuard.Abstractions;
using NecroGuard.Configuration;
using NecroGuard.Core;
using NecroGuard.Middleware;
using NecroGuard.Sanitizers;
using NecroGuard.Scanners;

namespace NecroGuard.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddNecroGuard(this IServiceCollection services, Action<NecroGuardOptions>? configureOptions = null)
    {
        if (configureOptions != null)
        {
            services.Configure(configureOptions);
        }
        else
        {
            services.Configure<NecroGuardOptions>(options => { });
        }

        // Register core services
        services.AddSingleton<ScannerPipelineOptions>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<NecroGuardOptions>>().Value;
            return new ScannerPipelineOptions
            {
                MaxConcurrentScanners = opts.MaxConcurrentScanners,
                ScannerTimeout = opts.ScannerTimeout
            };
        });
        services.AddSingleton<ScannerPipeline>();
        services.AddSingleton<INecroGuard, NecroGuardService>();

        // Register default scanners
        services.AddSingleton<IScanner, ImageScanner>();
        services.AddSingleton<IScanner, PdfScanner>();
        services.AddSingleton<IScanner, OfficeScanner>();
        services.AddSingleton<IScanner, TextScanner>();
        services.AddSingleton<IScanner, MetadataScanner>();

        // Register default sanitizers
        services.AddSingleton<ISanitizer, ImageSanitizer>();
        services.AddSingleton<ISanitizer, PdfSanitizer>();
        services.AddSingleton<ISanitizer, OfficeSanitizer>();
        services.AddSingleton<ISanitizer, TextSanitizer>();

        return services;
    }

    public static IApplicationBuilder UseNecroGuard(this IApplicationBuilder app, string pathPattern = "/api/ai")
    {
        return app.UseMiddleware<NecroGuardMiddleware>(pathPattern);
    }
}