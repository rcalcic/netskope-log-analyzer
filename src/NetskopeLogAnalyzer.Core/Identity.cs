using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

/// <summary>Um dado de identificação do usuário ou da máquina, com o arquivo de onde veio.</summary>
public sealed record IdentityItem(string Group, string Label, string Value, string Source);

/// <summary>
/// Junta tudo o que o pacote revela sobre quem é o usuário e qual é a máquina: e-mail registrado,
/// login do sistema, hostname, fabricante, série, IDs do Netskope, interfaces e forma de registro.
/// Os dados ficam só na análise local.
/// </summary>
public sealed class IdentityCollector
{
    public const string User = "Usuário", Machine = "Máquina", Netskope = "Netskope", Network = "Rede";
    private static readonly string[] GroupOrder = { User, Machine, Netskope, Network };
    private static readonly string[] Lead =
    {
        "E-mail registrado no Netskope", "Login no sistema operacional", "Último logon na máquina", "Forma de registro",
        "Hostname", "Fabricante", "Modelo", "Número de série", "Sistema", "Distribuição",
        "Tenant", "Versão do cliente", "Cliente instalado em",
    };

    private readonly Dictionary<(string, string), IdentityItem> _items = new();
    private readonly List<(string, string)> _order = new();
    private readonly Dictionary<string, int> _emails = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _emailSources = new();
    private long? _lastLogon, _installTs, _caTs;
    private bool _idp, _secureEnroll;

    private static readonly Regex EmailRe = new(@"[A-Za-z0-9._%+*-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", RegexOptions.CultureInvariant);
    private static readonly Regex ConfigEmailRe = new(@"user[Ee]mail[ =:]+([^\s,\]\[]+@[^\s,\]\[]+)", RegexOptions.CultureInvariant);
    private static readonly Regex HomeRe = new(@"(?:/home/|/Users/|[A-Za-z]:\\Users\\)([^/\\\s*]+)[/\\]", RegexOptions.CultureInvariant);

    // ------------------------------------------------------------------ coleta

    private void Set(string group, string label, string? value, string source, bool overwrite = false)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        var v = SafeText.Printable(value.Trim());
        if (v.Length > 300) v = v[..300] + "…";
        var key = (group, label);
        if (_items.TryGetValue(key, out var old))
        {
            // valor mascarado (com *) é substituído pelo valor completo, se aparecer
            if (!overwrite && !(old.Value.Contains('*') && !v.Contains('*'))) return;
        }
        else _order.Add(key);
        _items[key] = new IdentityItem(group, label, v, source);
    }

    private void Email(string? email, string source)
    {
        if (string.IsNullOrWhiteSpace(email)) return;
        email = email.Trim().TrimEnd('.', ',', ';', ')', ']');
        if (!EmailRe.IsMatch(email) || email.Length > 120) return;
        _emails[email] = _emails.GetValueOrDefault(email) + 1;
        _emailSources.Add(source);
    }

    /// <summary>Arquivos pequenos de texto (install.log, systeminfo, ipconfig, network-state…).</summary>
    public void OnFile(string baseName, string text)
    {
        var diag = Regex.Match(baseName, @"^nsDiag-(.+)\.log$", RegexOptions.IgnoreCase);
        if (diag.Success) Set(User, "Login no sistema operacional", diag.Groups[1].Value, baseName);
        if (text.Length > 5_000_000) return;

        if (baseName.Equals("install.log", StringComparison.OrdinalIgnoreCase)) Install(text, baseName);
        else if (baseName.Equals("appstatus", StringComparison.OrdinalIgnoreCase))
        {
            var ca = Regex.Match(text, @"CA_INSTALL_TIME=(\d{9,11})");
            if (ca.Success) _caTs = long.Parse(ca.Groups[1].Value, CultureInfo.InvariantCulture);
        }
        if (Regex.IsMatch(baseName, "network-state|ip[-_]?addr", RegexOptions.IgnoreCase)) LinuxInterfaces(text, baseName);
        if (Regex.IsMatch(baseName, "ipconfig", RegexOptions.IgnoreCase)) WindowsInterfaces(text, baseName);
        if (Regex.IsMatch(baseName, "systeminfo|sysinfo|computerinfo", RegexOptions.IgnoreCase) || text.Contains("OS Name:") || text.Contains("Nome do sistema operacional:")) SystemInfo(text, baseName);
        if (Regex.IsMatch(baseName, "sw_vers|scutil|hostinfo", RegexOptions.IgnoreCase)) MacInfo(text, baseName);
    }

    private void Install(string t, string src)
    {
        Set(User, "Login no sistema operacional", Regex.Match(t, @"Login User:\s*(\S+)").Groups[1].Value, src);
        var sudo = Regex.Match(t, @"SUDO User:\s*(\S+)").Groups[1].Value;
        var login = Regex.Match(t, @"Login User:\s*(\S+)").Groups[1].Value;
        if (sudo.Length > 0 && sudo != login) Set(User, "Instalado pelo usuário (sudo)", sudo, src);
        var sess = Regex.Match(t, @"Current login users:\s*\r?\n([\s\S]*?)(?:\r?\n-{5,}|\z)");
        if (sess.Success)
        {
            var users = sess.Groups[1].Value.Split('\n')
                .Select(l => Regex.Match(l.Trim(), @"^(\S+)\s+(\S+)"))
                .Where(m => m.Success)
                .Select(m => $"{m.Groups[1].Value} ({m.Groups[2].Value})")
                .Distinct().Take(6).ToList();
            if (users.Count > 0) Set(User, "Sessões abertas na instalação", string.Join(" · ", users), src);
        }
        var mode = Regex.Match(t, @"Install by (.+?) mode", RegexOptions.IgnoreCase);
        if (mode.Success)
        {
            var m = mode.Groups[1].Value.Trim().ToLowerInvariant();
            Set(User, "Forma de registro", m switch
            {
                "email invitation" => "Convite por e-mail",
                var x when x.Contains("idp") => "IdP (SSO)",
                var x when x.Contains("upn") => "UPN (usuário do domínio)",
                _ => mode.Groups[1].Value.Trim(),
            }, src);
        }
        Set(Machine, "Arquitetura", Regex.Match(t, @"Kernel arch:\s*(\S+)").Groups[1].Value, src);
        Set(Netskope, "Instalação registrada", Regex.Match(t, @"^Time:\s*(.+)$", RegexOptions.Multiline).Groups[1].Value, src);
        Email(Regex.Match(t, @"(?i)e-?mail[^:\r\n]*:\s*(\S+@\S+)").Groups[1].Value, src);
    }

    private void LinuxInterfaces(string t, string src)
    {
        var list = new List<string>();
        foreach (Match m in Regex.Matches(t, @"^\d+: ([^:@\s]+)(?:@\S+)?: <([^>]*)>[^\n]*\n((?:[ \t]+[^\n]*\n?)*)", RegexOptions.Multiline))
        {
            var name = m.Groups[1].Value; var flags = m.Groups[2].Value; var body = m.Groups[3].Value;
            if (name == "lo" || !flags.Contains("LOWER_UP")) continue;
            var ips = Regex.Matches(body, @"inet (\d+\.\d+\.\d+\.\d+/\d+)").Select(x => x.Groups[1].Value).ToList();
            if (ips.Count == 0) continue;
            var mac = Regex.Match(body, @"link/ether ([0-9a-f:]{17})").Groups[1].Value;
            list.Add($"{name}: {string.Join(", ", ips)}" + (mac.Length > 0 ? $" · MAC {mac}" : ""));
        }
        if (list.Count > 0) Set(Network, "Interfaces ativas", string.Join("\n", list.Take(8)), src);
    }

    private void WindowsInterfaces(string t, string src)
    {
        var list = new List<string>();
        foreach (var block in Regex.Split(t, @"\r?\n(?=\S[^\r\n]*:\s*\r?\n)"))
        {
            var head = Regex.Match(block, @"^\s*(\S[^\r\n]*?):\s*\r?\n").Groups[1].Value;
            var ip = Regex.Match(block, @"IPv4[^:\r\n]*:\s*(\d+\.\d+\.\d+\.\d+)").Groups[1].Value;
            if (ip.Length == 0 || head.Length == 0) continue;
            var mac = Regex.Match(block, @"(?:Physical Address|Endereço Físico|Endereço físico)[ .]*:\s*([0-9A-Fa-f-]{17})").Groups[1].Value;
            list.Add($"{Regex.Replace(head, @"^(Ethernet adapter|Wireless LAN adapter|Adaptador Ethernet|Adaptador de Rede sem Fio)\s*", "")}: {ip}" + (mac.Length > 0 ? $" · MAC {mac}" : ""));
        }
        if (list.Count > 0) Set(Network, "Interfaces ativas", string.Join("\n", list.Take(8)), src);
        Set(Machine, "Hostname", Regex.Match(t, @"(?:Host Name|Nome do host)[ .]*:\s*(\S+)").Groups[1].Value, src);
        Set(Machine, "Sufixo DNS primário", Regex.Match(t, @"(?:Primary Dns Suffix|Sufixo DNS primário)[ .]*:\s*(\S+)").Groups[1].Value, src);
    }

    private void SystemInfo(string t, string src)
    {
        string V(params string[] labels)
        {
            foreach (var l in labels)
            {
                var m = Regex.Match(t, "^" + Regex.Escape(l) + @":\s*(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
                if (m.Success) return m.Groups[1].Value;
            }
            return "";
        }
        Set(Machine, "Hostname", V("Host Name", "Nome do host"), src);
        var os = $"{V("OS Name", "Nome do sistema operacional")} {V("OS Version", "Versão do sistema operacional")}".Trim();
        Set(Machine, "Sistema", os, src, overwrite: os.Length > 0);
        Set(Machine, "Fabricante", V("System Manufacturer", "Fabricante do sistema"), src);
        Set(Machine, "Modelo", V("System Model", "Modelo do sistema"), src);
        Set(Machine, "Arquitetura", V("System Type", "Tipo de sistema"), src);
        Set(Machine, "BIOS", V("BIOS Version", "Versão do BIOS"), src);
        Set(Machine, "Domínio / grupo de trabalho", V("Domain", "Domínio"), src);
        Set(User, "Servidor de logon", V("Logon Server", "Servidor de Logon"), src);
        Set(User, "Proprietário registrado", V("Registered Owner", "Proprietário registrado"), src);
        Set(User, "Organização registrada", V("Registered Organization", "Organização registrada"), src);
        Set(Machine, "Instalação do Windows", V("Original Install Date", "Data da instalação original"), src);
        Set(Machine, "Último boot", V("System Boot Time", "Tempo de Inicialização do Sistema", "Hora da inicialização do sistema"), src);
        Set(Machine, "Memória física", V("Total Physical Memory", "Memória física total"), src);
        Set(Machine, "Fuso horário", V("Time Zone", "Fuso horário"), src);
    }

    private void MacInfo(string t, string src)
    {
        var name = Regex.Match(t, @"ProductName:\s*(.+)").Groups[1].Value.Trim();
        var ver = Regex.Match(t, @"ProductVersion:\s*(.+)").Groups[1].Value.Trim();
        if (name.Length > 0) Set(Machine, "Sistema", $"{name} {ver}".Trim(), src);
        Set(Machine, "Nome do computador", Regex.Match(t, @"ComputerName:\s*(.+)").Groups[1].Value, src);
    }

    /// <summary>Linhas de log: só as que carregam identidade (filtro barato antes de qualquer regex).</summary>
    public void OnLine(string msg, string file)
    {
        if (msg.Length > 16384) return;
        if (msg.Contains("seremail", StringComparison.OrdinalIgnoreCase) || msg.Contains("userEmail", StringComparison.Ordinal))
        {
            var m = ConfigEmailRe.Match(msg);
            if (m.Success) Email(m.Groups[1].Value, file);
            else { var u = Regex.Match(msg, @"useremail\s+(\S+@\S+)", RegexOptions.IgnoreCase); if (u.Success) Email(u.Groups[1].Value, file); }
        }
        if (msg.Contains("STA user agent: hostname:", StringComparison.Ordinal))
            Set(Machine, "Hostname", Regex.Match(msg, @"hostname:\s*(\S+)").Groups[1].Value, file);
        if (msg.Contains("Output zip file to", StringComparison.Ordinal) || msg.Contains("nsdiag", StringComparison.OrdinalIgnoreCase) && msg.Contains("Users", StringComparison.Ordinal))
        {
            var h = HomeRe.Match(msg);
            if (h.Success) Set(User, "Login no sistema operacional", h.Groups[1].Value, file);
        }
        if (msg.Contains("IdPProvisioning", StringComparison.Ordinal)) _idp = true;
        if (msg.Contains("m_enableSecureEnrollment = 1", StringComparison.Ordinal)) _secureEnroll = true;
        if (msg.Contains("Device Info: {", StringComparison.Ordinal)) DeviceInfo(msg[(msg.IndexOf("Device Info: {", StringComparison.Ordinal) + 13)..], file);
    }

    private void DeviceInfo(string json, string file)
    {
        try
        {
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 16 });
            var d = doc.RootElement;
            if (!d.TryGetProperty("device", out var dev) || dev.ValueKind != JsonValueKind.Object) return;
            if (dev.TryGetProperty("assessment", out var a) && a.ValueKind == JsonValueKind.Object)
            {
                Email(S(a, "user_email"), file);
                Set(Machine, "Hostname", S(a, "machine_name"), file);
                var distro = S(a, "os_distro");
                if (distro is { Length: > 0 }) Set(Machine, "Distribuição", distro, file);
                Set(Machine, "Disco principal criptografado", YesNo(S(a, "primary_storage_encrypted")), file, overwrite: true);
                Set(Machine, "Gerenciado (marcado no console)", YesNo(S(a, "managed")), file, overwrite: true);
                Set(User, "Modo por usuário (várias sessões)", YesNo(S(a, "perusermode")), file, overwrite: true);
                if (long.TryParse(S(a, "last_logon_time"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var ll) && ll > 1_000_000_000) _lastLogon = Math.Max(_lastLogon ?? 0, ll);
            }
            Set(Netskope, "ID do dispositivo Netskope", S(dev, "netskope_device_id"), file);
            Set(Netskope, "ID de hardware", S(dev, "hardware_identifier"), file);
        }
        catch (JsonException) { }
    }

    private static string? YesNo(string? v) => v?.ToLowerInvariant() switch { "true" or "1" => "sim", "false" or "0" => "não", _ => v };

    private static string? S(JsonElement e, params string[] path)
    {
        foreach (var p in path)
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(p, out e)) return null;
        return e.ValueKind switch
        {
            JsonValueKind.String => e.GetString(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => e.GetRawText(),
            _ => null,
        };
    }

    // ------------------------------------------------------------------ fechamento

    public void Finish(AnalysisResult r, IReadOnlyDictionary<string, JsonElement> json)
    {
        var F = r.Facts;
        string When(long epoch)
        {
            var utc = DateTimeOffset.FromUnixTimeSeconds(epoch).UtcDateTime;
            var local = r.LogUtcOffset is TimeSpan off ? utc + off : utc.ToLocalTime();
            return local.ToString("dd/MM/yyyy HH:mm", CultureInfo.InvariantCulture);
        }

        JsonElement c = default;
        var hasCfg = json.TryGetValue("nsconfig.json", out c) || json.TryGetValue("nsconfig.json.bak", out c);
        if (hasCfg)
        {
            Email(S(c, "cache", "lastClientConfigUserEmail"), "nsconfig.json");
            Set(Machine, "Hostname", S(c, "cache", "device", "hostname"), "nsconfig.json", overwrite: true);
            Set(Machine, "Fabricante", S(c, "cache", "device", "make"), "nsconfig.json");
            Set(Machine, "Modelo", S(c, "cache", "device", "model"), "nsconfig.json");
            Set(Machine, "Número de série", S(c, "cache", "device", "serial_num"), "nsconfig.json");
            var os = $"{S(c, "cache", "device", "os")} {S(c, "cache", "device", "os_version")}".Trim();
            Set(Machine, "Sistema", os, "nsconfig.json");
            Set(Netskope, "Versão do cliente", S(c, "cache", "device", "ns_version"), "nsconfig.json");
            if (long.TryParse(S(c, "cache", "appinstalltimestamp"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var it) && it > 1_000_000_000) _installTs = it;
            Set(Netskope, "Configuração do cliente", S(c, "clientConfig", "configurationName"), "nsconfig.json");
            var lcv = S(c, "cache", "lastClientConfigVersion");
            if (lcv is { Length: > 0 }) Set(Netskope, "Versão da configuração recebida", lcv, "nsconfig.json");
            Set(User, "Grupo/OU de provisionamento", S(c, "clientConfig", "ou_or_group_name"), "nsconfig.json");
            var tags = S(c, "cache", "install_tags");
            if (tags is { Length: > 0 }) Set(Machine, "Tags de instalação", tags, "nsconfig.json");
            var gw = S(c, "nsgw", "host");
            var tenant = gw is null ? null : Regex.Match(gw, @"^gateway-(.+?)\.goskope\.com$").Groups[1].Value;
            Set(Netskope, "Tenant", tenant is { Length: > 0 } ? tenant : F.TenantHost, "nsconfig.json");
            Set(Netskope, "Tenant do Private Access", S(c, "npa", "tenant"), "nsconfig.json");
        }
        if (json.TryGetValue("nsuser.conf", out var u))
        {
            Set(User, "Usuário habilitado no Netskope", YesNo(S(u, "cache", "userStatus")), "nsuser.conf");
            Set(User, "Usuário habilitado no Private Access", YesNo(S(u, "cache", "npaUserStatus")), "nsuser.conf");
            var dc = S(u, "cache", "DeviceClassificationStatus");
            Set(Machine, "Classificação do dispositivo", dc == "not configured" ? "não configurada" : dc, "nsuser.conf");
            var dt = S(u, "cache", "device_tags");
            if (dt is { Length: > 0 } && dt != "[]") Set(Machine, "Tags do dispositivo", dt.Trim('[', ']').Replace("\"", ""), "nsuser.conf");
            Set(Netskope, "ID do túnel", S(u, "cache", "tunnelId"), "nsuser.conf");
        }

        // e-mail: o mais frequente sem máscara; senão o mascarado
        var best = _emails.OrderBy(kv => kv.Key.Contains('*') ? 1 : 0).ThenByDescending(kv => kv.Value).Select(kv => kv.Key).FirstOrDefault();
        if (best != null)
        {
            var src = hasCfg && S(c, "cache", "lastClientConfigUserEmail") == best ? "nsconfig.json" : string.Join(", ", _emailSources.Take(3));
            Set(User, "E-mail registrado no Netskope", best + (best.Contains('*') ? " (mascarado no log)" : ""), src, overwrite: true);
            var others = _emails.Keys.Where(e => !e.Equals(best, StringComparison.OrdinalIgnoreCase) && !e.Contains('*')).Take(4).ToList();
            if (others.Count > 0) Set(User, "Outros e-mails no registro", string.Join(" · ", others), "logs do cliente");
        }
        if (_idp && !_items.ContainsKey((User, "Forma de registro"))) Set(User, "Forma de registro", "IdP (SSO)", "nsAppUI.log");
        else if (_idp) Set(User, "Autenticação IdP", "janela de login do IdP usada pelo cliente", "nsAppUI.log");
        if (_secureEnroll) Set(User, "Registro seguro (secure enrollment)", "ativo", "nsAppUI.log");
        if (_lastLogon is long ll) Set(User, "Último logon na máquina", When(ll), "npadebuglog.log");
        if (_installTs is long its) Set(Netskope, "Cliente instalado em", When(its), "nsconfig.json");
        if (_caTs is long cts) Set(Netskope, "Certificado (CA) instalado em", When(cts), "appstatus");

        Set(Machine, "Hostname", F.Host, "logs");
        Set(Machine, "Sistema", F.OsName ?? F.Os, "install.log");
        Set(Netskope, "Versão do cliente", F.Version, "logs");
        Set(Netskope, "Steering", F.Steering, "logs");
        Set(Network, "IP de saída (visto pelo Netskope)", F.Egress, "logs");
        Set(Network, "POP Internet / Private Access", string.Join(" / ", new[] { F.PopSwg, F.PopNpa }.Where(x => !string.IsNullOrEmpty(x))), "logs");
        Set(Network, "DNS da máquina", F.Dns, "network-state.log");
        Set(Network, "Dentro da empresa (on-prem)", F.OnPrem, "logs");

        r.Identity.Clear();
        foreach (var g in GroupOrder)
            r.Identity.AddRange(_order.Where(k => k.Item1 == g)
                .Select((k, idx) => (Item: _items[k], Rank: Array.IndexOf(Lead, k.Item2) is var p && p >= 0 ? p : 100 + idx))
                .OrderBy(x => x.Rank).Select(x => x.Item));
    }
}
