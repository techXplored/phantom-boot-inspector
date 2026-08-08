namespace TechXplored.PhantomBootInspector;

internal sealed class BcdObject
{
    public BcdObject(string section) => Section = section;

    public string Section { get; }
    public Dictionary<string, List<string>> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Identifier => First("identifier");

    public string? First(string key) =>
        Properties.TryGetValue(key, out List<string>? values) ? values.FirstOrDefault() : null;

    public IEnumerable<string> Values(string key) =>
        Properties.TryGetValue(key, out List<string>? values) ? values : Enumerable.Empty<string>();

    public string AllValues => string.Join(
        Environment.NewLine,
        Properties.SelectMany(p => p.Value.Select(v => $"{p.Key}={v}")));

    public void Add(string key, string value)
    {
        if (!Properties.TryGetValue(key, out List<string>? values))
        {
            values = new List<string>();
            Properties[key] = values;
        }

        values.Add(value);
    }
}

internal enum Severity
{
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4
}

internal sealed record Finding(
    Severity Severity,
    string Title,
    string? Identifier,
    string Reason,
    string Evidence,
    string? RemediationPreview = null);

internal sealed class InspectionReport
{
    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.Now;
    public bool Elevated { get; init; }
    public int ObjectsExamined { get; init; }
    public int BootMenuEntries { get; init; }
    public List<Finding> Findings { get; init; } = new();
}
