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
    public required string Category { get; set; }
    public required string Title { get; set; }
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
    /// <summary>Sintomas selecionados pelo analista aos quais este item se relaciona.</summary>
    public List<string> FocusTags { get; } = new();
    public string? ExplorerQuery { get; init; }

    // usados só pela detecção de ambiente, para montar os comandos
    public List<string> Interfaces { get; } = new();
    public List<string> MissingPackages { get; } = new();

    /// <summary>Horário de cada ocorrência (usado na correlação de causa raiz).</summary>
    public List<DateTime> Times { get; } = new();

    /// <summary>Última ocorrência mais de 24 h antes da coleta (ou do horário informado): conta como histórico, não como problema atual.</summary>
    public bool Historical { get; set; }
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

    // ---- v3: telemetria, baseline, experiência e causa raiz
    public Dictionary<string, MetricSeries> Series { get; } = new(StringComparer.OrdinalIgnoreCase);
    public List<Snapshot> Snapshots { get; } = new();
    public List<PathTrace> Paths { get; } = new();
    public List<AppUsage> Apps { get; } = new();
    public List<PopStat> Pops { get; } = new();
    public List<StateInterval> States { get; } = new();
    public Dictionary<string, double> Availability { get; } = new();
    public List<KeyValuePair<DateTime, string>> EgressHistory { get; } = new();
    public List<ScoreWindow> Scores { get; } = new();
    public double? Score { get; set; }
    public List<Incident> Incidents { get; } = new();
    public List<Anomaly> Anomalies { get; } = new();
    /// <summary>Informações estáticas do dispositivo (CPU, RAM, SO…), vindas do coletor e de snapshots.</summary>
    public Dictionary<string, string> Device { get; } = new();
    public bool HasTelemetry { get; set; }
    public List<string> TelemetrySources { get; } = new();
    /// <summary>Avisos sobre dados ausentes (o que não pôde ser medido e por quê).</summary>
    public List<string> DataGaps { get; } = new();
    /// <summary>Quem é o usuário e qual é a máquina (e-mail, login, hostname, série, IDs, interfaces).</summary>
    public List<IdentityItem> Identity { get; } = new();
    /// <summary>Comparação com a análise anterior da mesma máquina (histórico local), quando houver.</summary>
    public HistoryComparison? History { get; set; }

    // ---- v3.1: visão de TAC
    public List<ConfigItem> Config { get; } = new();
    public List<InterfaceDns> DnsInterfaces { get; } = new();
    public List<SourceCoverage> Coverage { get; } = new();
    public List<NpaSession> NpaSessions { get; } = new();
    public List<PerfMetric> Performance { get; } = new();
    public List<CaptureSummary> Captures { get; } = new();
    /// <summary>Roteiro de perguntas do TAC respondido automaticamente (pergunta → resposta).</summary>
    public List<KeyValuePair<string, string>> CaseSummary { get; } = new();
    /// <summary>Componentes do score que tiveram dados (ex.: "Rede, Netskope"); vazio = completo.</summary>
    public string? ScoreMissing { get; set; }
    /// <summary>Fuso horário registrado nos logs do usuário (ex.: −03:00). Os horários exibidos são os da máquina do usuário.</summary>
    public TimeSpan? LogUtcOffset { get; set; }

    // ---- v4: análise direcionada pelo sintoma relatado
    public AnalysisOptions Options { get; set; } = new();
    public List<FocusResult> Focus { get; } = new();
    public DomainReport? Domain { get; set; }
    /// <summary>Padrões de exceção (bypass) do steering: seção → domínio/IP.</summary>
    public List<KeyValuePair<string, string>> ExceptionPatterns { get; } = new();
    /// <summary>Processos com certificado fixo (ficam fora da inspeção).</summary>
    public List<string> CertPinnedApps { get; } = new();

    public MetricSeries GetOrAddSeries(string key, Func<MetricSeries> create)
    {
        if (!Series.TryGetValue(key, out var s)) { s = create(); Series[key] = s; }
        return s;
    }

    /// <summary>Itens atuais (não históricos) com a gravidade pedida.</summary>
    public int Count(Severity s) => Findings.Count(f => f.Severity == s && !f.Historical);
    public int CountHistorical(Severity s) => Findings.Count(f => f.Severity == s && f.Historical);
    /// <summary>Momento de referência da análise: horário informado pelo usuário ou fim dos logs.</summary>
    public DateTime? ReferenceTime { get; set; }
    public int RawErrors => Files.Sum(f => f.Errors);
    public int RawWarnings => Files.Sum(f => f.Warnings);
}
