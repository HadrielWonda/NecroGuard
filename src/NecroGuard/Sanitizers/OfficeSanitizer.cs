using NecroGuard.Abstractions;
using NecroGuard.Abstractions.Models;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Wordprocessing;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml.Presentation;
using System.IO.Compression;
using System.Text;

namespace NecroGuard.Sanitizers;

public class OfficeSanitizer : ISanitizer
{
    public string Name => "OfficeSanitizer";

    public bool CanHandle(ScanResult scanResult)
    {
        return scanResult.Threats.Any(t => t.ScannerName == "OfficeScanner");
    }

    public async Task<Stream> SanitizeAsync(Stream input, ScanResult result, CancellationToken cancellationToken = default)
    {
        var outputStream = new MemoryStream();
        input.Position = 0;

        // For Open XML formats, we can use DocumentFormat.OpenXml to modify the package
        // For simplicity, we'll handle Word documents (DOCX) as an example.
        // Extend to Excel and PowerPoint similarly.
        using (var doc = WordprocessingDocument.Open(input, false))
        {
            if (doc != null)
            {
                // Create a new copy
                using (var newDoc = WordprocessingDocument.Create(outputStream, doc.DocumentType))
                {
                    // Clone the main document part without VBA project
                    var mainPart = newDoc.AddMainDocumentPart();
                    mainPart.Document = (Document)doc.MainDocumentPart.Document.CloneNode(true);
                    // Remove any VBA project (macros)
                    newDoc.VbaProjectPart = null;
                    // Remove hidden text runs
                    var hiddenRuns = mainPart.Document.Descendants<Run>().Where(r => r.RunProperties?.Hidden?.Val?.Value == true);
                    foreach (var run in hiddenRuns.ToList())
                    {
                        run.Remove();
                    }
                    // Remove comments
                    var commentsPart = mainPart.CommentsPart;
                    if (commentsPart != null) mainPart.DeletePart(commentsPart);
                    // Save
                    mainPart.Document.Save();
                }
            }
            else
            {
                // Fallback: copy original
                await input.CopyToAsync(outputStream, cancellationToken);
            }
        }

        outputStream.Position = 0;
        return outputStream;
    }
}