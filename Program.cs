using System.Security.Principal;
using System.Text.Json;

namespace TechXplored.PhantomBootInspector;

internal static class Program
{
    public static int Main(string[] args)
    {
        bool json = args.Contains("--json", StringComparer.OrdinalIgnoreCase);
        bool preview = args.Contains("--preview-remediation", StringComparer.OrdinalIgnoreCase);

        try
        {
            bool elevated = IsAdministrator();
            var reader = new BcdReader();
            IReadOnlyList<BcdObject> objects = reader.ReadAll();
            var inspector = new BootInspector(objects);
            InspectionReport report = inspector.Inspect(elevated, preview);

            if (json)
            {
                Console.WriteLine(JsonSerializer.Serialize(report, new JsonSerializerOptions
                {
                    WriteIndented = true
                }));
            }
            else
            {
                ConsoleReporter.Write(report);
            }

            return report.Findings.Any(f => f.Severity is Severity.Critical or Severity.High) ? 2 : 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("TechXplored Phantom Boot Entry Inspector failed.");
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static bool IsAdministrator()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}

internal static class ConsoleReporter
{
    public static void Write(InspectionReport report)
    {
        Console.WriteLine();
        Console.WriteLine("TECHXPLORED PHANTOM BOOT ENTRY INSPECTOR");
        Console.WriteLine("=======================================");
        Console.WriteLine($"BCD objects examined : {report.ObjectsExamined}");
        Console.WriteLine($"Boot-menu entries    : {report.BootMenuEntries}");
        Console.WriteLine($"Running elevated     : {(report.Elevated ? "Yes" : "No")}");
        Console.WriteLine();

        if (!report.Elevated)
        {
            Console.WriteLine("NOTE: Run as Administrator for the most reliable BCD inspection.");
            Console.WriteLine();
        }

        if (report.Findings.Count == 0)
        {
            Console.WriteLine("RESULT: No obvious phantom boot entries found.");
            Console.WriteLine("No BCD entries were changed.");
            return;
        }

        foreach (Finding finding in report.Findings.OrderBy(f => f.Severity))
        {
            Console.WriteLine($"[{finding.Severity.ToString().ToUpperInvariant()}] {finding.Title}");
            if (!string.IsNullOrWhiteSpace(finding.Identifier))
                Console.WriteLine($"  Entry:    {finding.Identifier}");
            Console.WriteLine($"  Reason:   {finding.Reason}");
            Console.WriteLine($"  Evidence: {finding.Evidence}");
            if (!string.IsNullOrWhiteSpace(finding.RemediationPreview))
                Console.WriteLine($"  Preview:  {finding.RemediationPreview}");
            Console.WriteLine();
        }

        Console.WriteLine("No BCD entries were changed.");
    }
}
