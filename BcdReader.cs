using System.Diagnostics;
using System.Text.RegularExpressions;

namespace TechXplored.PhantomBootInspector;

internal sealed class BcdReader
{
    private static readonly Regex PropertyRegex = new(
        @"^\s*([A-Za-z][A-Za-z0-9_-]*)\s{2,}(.+?)\s*$",
        RegexOptions.Compiled);

    public IReadOnlyList<BcdObject> ReadAll()
    {
        string output = RunBcdEdit();
        return Parse(output);
    }

    private static string RunBcdEdit()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "bcdedit.exe",
            Arguments = "/enum all /v",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using Process process = Process.Start(psi)
            ?? throw new InvalidOperationException("Unable to start bcdedit.exe.");

        string stdout = process.StandardOutput.ReadToEnd();
        string stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"BCDEdit returned exit code {process.ExitCode}: {stderr.Trim()}");
        }

        if (string.IsNullOrWhiteSpace(stdout))
            throw new InvalidOperationException("BCDEdit returned no data.");

        return stdout;
    }

    internal static IReadOnlyList<BcdObject> Parse(string text)
    {
        string[] lines = text.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var objects = new List<BcdObject>();
        BcdObject? current = null;
        string? currentProperty = null;

        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];

            if (i + 1 < lines.Length && !string.IsNullOrWhiteSpace(line) && IsDashLine(lines[i + 1]))
            {
                current = new BcdObject(line.Trim());
                objects.Add(current);
                currentProperty = null;
                i++;
                continue;
            }

            if (current is null || string.IsNullOrWhiteSpace(line))
                continue;

            Match match = PropertyRegex.Match(line);
            if (match.Success)
            {
                currentProperty = match.Groups[1].Value.Trim();
                current.Add(currentProperty, match.Groups[2].Value.Trim());
                continue;
            }

            if (currentProperty is not null && char.IsWhiteSpace(line[0]))
                current.Add(currentProperty, line.Trim());
        }

        return objects;
    }

    private static bool IsDashLine(string line)
    {
        string value = line.Trim();
        return value.Length >= 3 && value.All(c => c == '-');
    }
}
