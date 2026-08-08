using System.Text.RegularExpressions;

namespace TechXplored.PhantomBootInspector;

internal sealed class BootInspector
{
    private const string BootManagerGuid = "{9dea862c-5cdd-4e70-acc1-f32b344d4795}";

    private readonly IReadOnlyList<BcdObject> _objects;
    private readonly Dictionary<string, BcdObject> _byId;

    public BootInspector(IReadOnlyList<BcdObject> objects)
    {
        _objects = objects;
        _byId = objects
            .Where(o => !string.IsNullOrWhiteSpace(o.Identifier))
            .GroupBy(o => NormalizeId(o.Identifier!))
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
    }

    public InspectionReport Inspect(bool elevated, bool previewRemediation)
    {
        var findings = new List<Finding>();
        BcdObject? bootManager = FindBootManager();

        if (bootManager is null)
        {
            findings.Add(new Finding(
                Severity.Critical,
                "Windows Boot Manager object not found",
                null,
                "The BCD enumeration did not contain an identifiable Windows Boot Manager object.",
                "The inspector cannot safely determine the visible boot-menu entries."));

            return BuildReport(elevated, 0, findings);
        }

        List<string> menuIds = ExtractIdentifiers(bootManager.Values("displayorder"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        InspectMenuReferences(menuIds, findings, previewRemediation);
        InspectMenuEntries(menuIds, findings, previewRemediation);
        InspectDuplicateTargets(menuIds, findings);
        InspectHiddenSetupRemnants(menuIds, findings);

        return BuildReport(elevated, menuIds.Count, Deduplicate(findings));
    }

    private BcdObject? FindBootManager()
    {
        if (_byId.TryGetValue(NormalizeId(BootManagerGuid), out BcdObject? exact))
            return exact;

        return _objects.FirstOrDefault(o =>
            o.Values("displayorder").Any() &&
            o.Values("default").Any() &&
            o.Values("timeout").Any());
    }

    private void InspectMenuReferences(List<string> menuIds, List<Finding> findings, bool preview)
    {
        foreach (string id in menuIds)
        {
            if (_byId.ContainsKey(NormalizeId(id)))
                continue;

            findings.Add(new Finding(
                Severity.High,
                "Boot menu references a missing BCD object",
                id,
                "Windows Boot Manager lists this identifier in displayorder, but the referenced object was not returned by BCDEdit.",
                "A stale displayorder reference can create a phantom or unusable boot-menu choice.",
                preview ? $"bcdedit /displayorder {id} /remove" : null));
        }
    }

    private void InspectMenuEntries(List<string> menuIds, List<Finding> findings, bool preview)
    {
        foreach (string id in menuIds)
        {
            if (!_byId.TryGetValue(NormalizeId(id), out BcdObject? entry))
                continue;

            string description = entry.First("description") ?? "(no description)";

            if (ContainsSetupTempPath(entry.AllValues))
            {
                findings.Add(new Finding(
                    Severity.High,
                    "Boot entry points into temporary Windows Setup files",
                    id,
                    "This visible boot entry references $Windows.~BT or another Windows Setup temporary path.",
                    FindEvidence(entry, "$Windows.~BT", "Windows.~BT"),
                    preview ? $"bcdedit /displayorder {id} /remove" : null));
            }

            if (LooksTemporary(description))
            {
                findings.Add(new Finding(
                    Severity.Medium,
                    "Boot entry looks like a setup or rollback remnant",
                    id,
                    $"The visible description is \"{description}\".",
                    "Setup, rollback, and temporary installation entries normally should not remain in the standard boot menu after installation completes.",
                    preview ? $"bcdedit /displayorder {id} /remove" : null));
            }

            ValidateDriveLetterReference(id, entry, "device", findings, preview);
            ValidateDriveLetterReference(id, entry, "osdevice", findings, preview);
            ValidateSystemRoot(id, entry, findings, preview);
            ValidateLoaderPath(id, entry, findings, preview);
        }
    }

    private static void ValidateDriveLetterReference(
        string id,
        BcdObject entry,
        string property,
        List<Finding> findings,
        bool preview)
    {
        string? value = entry.First(property);
        string? root = TryGetDriveRoot(value);

        if (root is null)
            return;

        if (Directory.Exists(root))
            return;

        findings.Add(new Finding(
            Severity.High,
            $"Boot entry references a missing {property} volume",
            id,
            $"The {property} property points to {root}, but that volume is not currently accessible.",
            $"{property} = {value}",
            preview ? $"bcdedit /displayorder {id} /remove" : null));
    }

    private static void ValidateSystemRoot(
        string id,
        BcdObject entry,
        List<Finding> findings,
        bool preview)
    {
        string? root = TryGetDriveRoot(entry.First("osdevice"));
        string? systemRoot = entry.First("systemroot");

        if (root is null || string.IsNullOrWhiteSpace(systemRoot) || !Directory.Exists(root))
            return;

        string expected = Path.Combine(root, systemRoot.Trim().TrimStart('\\', '/'));
        if (Directory.Exists(expected))
            return;

        findings.Add(new Finding(
            Severity.High,
            "Windows system directory referenced by boot entry is missing",
            id,
            $"The entry expects a Windows system root at {expected}, but that directory does not exist.",
            $"osdevice = {entry.First("osdevice")}; systemroot = {systemRoot}",
            preview ? $"bcdedit /displayorder {id} /remove" : null));
    }

    private static void ValidateLoaderPath(
        string id,
        BcdObject entry,
        List<Finding> findings,
        bool preview)
    {
        string? loaderPath = entry.First("path");
        string? root = TryGetDriveRoot(entry.First("device"));

        if (root is null || string.IsNullOrWhiteSpace(loaderPath) || !Directory.Exists(root))
            return;

        if (!loaderPath.Contains("winload", StringComparison.OrdinalIgnoreCase))
            return;

        string expected = Path.Combine(root, loaderPath.Trim().TrimStart('\\', '/'));
        if (File.Exists(expected))
            return;

        findings.Add(new Finding(
            Severity.High,
            "Windows loader referenced by boot entry is missing",
            id,
            $"The BCD entry expects a Windows loader at {expected}, but the file does not exist.",
            $"device = {entry.First("device")}; path = {loaderPath}",
            preview ? $"bcdedit /displayorder {id} /remove" : null));
    }

    private void InspectDuplicateTargets(List<string> menuIds, List<Finding> findings)
    {
        var visible = menuIds
            .Where(id => _byId.ContainsKey(NormalizeId(id)))
            .Select(id => new { Id = id, Entry = _byId[NormalizeId(id)] })
            .ToList();

        foreach (var group in visible
                     .GroupBy(x => TargetSignature(x.Entry), StringComparer.OrdinalIgnoreCase)
                     .Where(g => !string.IsNullOrWhiteSpace(g.Key) && g.Count() > 1))
        {
            string ids = string.Join(", ", group.Select(x => x.Id));
            findings.Add(new Finding(
                Severity.Medium,
                "Multiple boot-menu entries appear to target the same Windows installation",
                ids,
                "Two or more visible entries share the same device, OS device, loader path, and system root.",
                $"Target signature: {group.Key}",
                "Review the entries and remove only the unwanted identifier from displayorder."));
        }
    }

    private void InspectHiddenSetupRemnants(List<string> menuIds, List<Finding> findings)
    {
        HashSet<string> visible = menuIds
            .Select(NormalizeId)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (BcdObject entry in _objects)
        {
            if (string.IsNullOrWhiteSpace(entry.Identifier) || visible.Contains(NormalizeId(entry.Identifier)))
                continue;

            if (!ContainsSetupTempPath(entry.AllValues))
                continue;

            findings.Add(new Finding(
                Severity.Low,
                "Windows Setup BCD remnant found outside the visible boot menu",
                entry.Identifier,
                "This BCD object references temporary Windows Setup storage but is not currently listed in Boot Manager displayorder.",
                FindEvidence(entry, "$Windows.~BT", "Windows.~BT")));
        }
    }

    private InspectionReport BuildReport(bool elevated, int menuEntries, List<Finding> findings) => new()
    {
        Elevated = elevated,
        ObjectsExamined = _objects.Count,
        BootMenuEntries = menuEntries,
        Findings = findings
    };

    private static List<Finding> Deduplicate(IEnumerable<Finding> findings) =>
        findings
            .GroupBy(f => $"{f.Severity}|{f.Title}|{f.Identifier}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

    private static IEnumerable<string> ExtractIdentifiers(IEnumerable<string> values)
    {
        foreach (string value in values)
        {
            foreach (Match match in Regex.Matches(value, @"\{[^}]+\}"))
                yield return match.Value;
        }
    }

    private static string TargetSignature(BcdObject entry) => string.Join("|", new[]
    {
        Normalize(entry.First("device")),
        Normalize(entry.First("osdevice")),
        Normalize(entry.First("path")),
        Normalize(entry.First("systemroot"))
    });

    private static bool ContainsSetupTempPath(string text) =>
        text.Contains("$Windows.~BT", StringComparison.OrdinalIgnoreCase) ||
        text.Contains("Windows.~BT", StringComparison.OrdinalIgnoreCase);

    private static bool LooksTemporary(string description)
    {
        string[] terms = { "windows setup", "windows rollback", "rollback", "temporary", "installation", "preinstallation" };
        return terms.Any(term => description.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    private static string FindEvidence(BcdObject entry, params string[] terms)
    {
        foreach ((string key, List<string> values) in entry.Properties)
        {
            foreach (string value in values)
            {
                if (terms.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase)))
                    return $"{key} = {value}";
            }
        }

        return "Matching setup-remnant evidence detected in the BCD object.";
    }

    private static string? TryGetDriveRoot(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith("partition=", StringComparison.OrdinalIgnoreCase))
            return null;

        string partition = value["partition=".Length..].Trim();
        return Regex.IsMatch(partition, @"^[A-Za-z]:$") ? partition + "\\" : null;
    }

    private static string NormalizeId(string value) => value.Trim().ToLowerInvariant();
    private static string Normalize(string? value) => value?.Trim().ToLowerInvariant() ?? string.Empty;
}
