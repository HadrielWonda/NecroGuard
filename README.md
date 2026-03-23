# NecroGuard

Protect AI applications from hidden prompts (zombie prompts) in images, documents, and text.

## Features

- Detects steganography, invisible Unicode, macros, and encoded payloads.
- Sanitizes content to remove threats.
- Extensible scanner pipeline.
- ASP.NET Core middleware for automatic scanning.

## Quick Start

1. Install the NuGet package: `dotnet add package NecroGuard`
2. Add to services:
   ```csharp
   builder.Services.AddNecroGuard(options => { options.StrictMode = true; });
   ```

3. Use middleware:
```csharp
    app.UseNecroGuard("/ai");
```

4. Or manually scan:
```csharp
 var result = await necroGuard.ScanAsync(stream, contentType);
 ```



 ## Documentation
 See the docs folder for full API reference and configuration options.


---

