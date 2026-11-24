namespace NetskopeLogAnalyzer.Core;

public enum LogLevel { Debug, Info, Warn, Error, Critical }

public enum Severity { Critical = 0, Warning = 1, Info = 2, Noise = 3 }

public enum EventKind { Good, Bad, Alert, Info }

public enum ClientOs { Windows, Linux, Mac }

/// <summary>Um arquivo de entrada (já extraído de um zip, se for o caso).</summary>
public sealed record SourceItem(string Name, byte[] Data);

/// <summary>Uma linha de log reconhecida.</summary>
public sealed record LogEntry(int FileIndex, DateTime Time, LogLevel Level, string Line, string Message, string Source);

public sealed class LogFileInfo
{
    public required string Name { get; init; }
    public string BaseName => Path.GetFileName(Name.Replace('\\', '/'));
    public long Size { get; init; }
    public int Lines { get; set; }
    public int Errors { get; set; }
    public int Warnings { get; set; }
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }
}

public sealed record TimelineEvent(DateTime Time, string Label, EventKind Kind, string Detail, string File);

public sealed record FixStep(string Text, string? Command = null);

public sealed record Reference(string Title, string Url);

public sealed class Finding
{
    public required string Key { get; init; }
    public Severity Severity { get; set; }
    public required string Category { get; init; }
    public required string Title { get; init; }
    public required string Meaning { get; set; }
    public string Action { get; init; } = "";
    public int Count { get; set; }
    public DateTime? First { get; set; }
    public DateTime? Last { get; set; }
    public List<string> Files { get; } = new();
    public List<string> Samples { get; } = new();
    public List<KeyValuePair<string, int>> Details { get; } = new();
    public List<FixStep> Steps { get; } = new();
    public List<Reference> References { get; } = new();
    public string SearchQuery { get; set; } = "";
    public string? ExplorerQuery { get; init; }

    // usados só pela detecção de ambiente, para montar os comandos
    public List<string> Interfaces { get; } = new();
    public List<string> MissingPackages { get; } = new();
}

public sealed class UnclassifiedGroup
{
    public required string Key { get; init; }
    public LogLevel Level { get; set; }
    public int Count { get; set; }
    public HashSet<string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
    public DateTime Last { get; set; }
    public required string Sample { get; init; }
}

public sealed record ServiceState(string Event, DateTime Time);

public sealed class Facts
{
    public string? Host { get; set; }
    public string? OsName { get; set; }
    public string? Os { get; set; }
    public string? Model { get; set; }
    public string? Version { get; set; }
    public string? InstallVersion { get; set; }
    public string? InstallTime { get; set; }
    public string? TenantId { get; set; }
    public string? TenantHost { get; set; }
    public string? Steering { get; set; }
    public string? ClientConfig { get; set; }
    public string? OnPrem { get; set; }
    public string? Egress { get; set; }
    public string? PopNpa { get; set; }
    public string? PopSwg { get; set; }
    public string? GatewayIp { get; set; }
    public string? Dns { get; set; }
    public string? FailClose { get; set; }
    public string? AllowDisable { get; set; }
    public string? InstalledVpnApps { get; set; }
    public string? NpaLast { get; set; }
    public string? ServiceStatus { get; set; }
    public string? NpaStatus { get; set; }
    /// <summary>Último evento por serviço (1 = Internet/SWG, 2 = Private Access/NPA).</summary>
    public Dictionary<int, ServiceState> Services { get; } = new();
}

public sealed class AnalysisResult
{
    public Facts Facts { get; } = new();
    public List<LogFileInfo> Files { get; } = new();
    public List<LogEntry> Entries { get; } = new();
    public List<TimelineEvent> Events { get; } = new();
    public List<Finding> Findings { get; } = new();
    public List<UnclassifiedGroup> Unclassified { get; } = new();
    public List<string> Skipped { get; } = new();
    public DateTime? Start { get; set; }
    public DateTime? End { get; set; }
    public ClientOs? DetectedOs { get; set; }

    public int Count(Severity s) => Findings.Count(f => f.Severity == s);
    public int RawErrors => Files.Sum(f => f.Errors);
    public int RawWarnings => Files.Sum(f => f.Warnings);
}
