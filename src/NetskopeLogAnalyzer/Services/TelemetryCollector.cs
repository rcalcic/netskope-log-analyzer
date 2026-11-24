using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using NetskopeLogAnalyzer.Core;

namespace NetskopeLogAnalyzer.Services;

/// <summary>
/// Coletor de telemetria (equivalente ao agente do DEM, sem licença): grava em JSON Lines amostras de
/// CPU, memória, disco, bateria, Wi-Fi, tráfego, processos, ping/perda/jitter, conexão TCP até os POPs,
/// DNS, testes HTTP por fase (curl.exe), traceroute até o POP e eventos de rede/energia/Netskope.
/// Formato documentado em <see cref="TelemetryParser"/>.
/// </summary>
public sealed class TelemetryCollector : IDisposable
{
    public const string MutexName = @"Local\NetskopeLogAnalyzer.Collector";
    public const string StopEventName = @"Local\NetskopeLogAnalyzer.Collector.Stop";

    private readonly AppSettings _o;
    private readonly object _lock = new();
    private StreamWriter? _w;
    private DateTime _fileDay;
    private readonly string _host = Environment.MachineName;
    private readonly int _cores = Environment.ProcessorCount;
    private ulong _lastIdle, _lastKernel, _lastUser;
    private long _lastRx, _lastTx; private DateTime _lastNet;
    private readonly Dictionary<int, (string Name, TimeSpan Cpu)> _lastProc = new();
    private DateTime _lastProcAt;
    private string? _lastGateway, _lastDns, _lastNs;
    private bool? _hasWifi;
    private DateTime _lastDisk = DateTime.MinValue, _lastTrace = DateTime.MinValue, _lastProbe = DateTime.MinValue, _lastNsCheck = DateTime.MinValue;

    public long Samples { get; private set; }
    public string? CurrentFile { get; private set; }

    public TelemetryCollector(AppSettings settings) => _o = settings;

    private string? Tenant => AppSettings.PolicyTenant ?? _o.Tenant;

    public async Task RunAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(AppSettings.TelemetryDir);
        Cleanup();
        NetworkChange.NetworkAddressChanged += OnAddressChanged;
        SystemEvents.PowerModeChanged += OnPower;
        Event("collector-start", $"intervalo {_o.IntervalSeconds}s");
        try
        {
            SampleCpu(prime: true);
            SampleNet(prime: true);
            SampleProcesses(prime: true);
            await Task.Delay(TimeSpan.FromSeconds(Math.Min(5, _o.IntervalSeconds)), ct);
            while (!ct.IsCancellationRequested)
            {
                var started = DateTime.Now;
                Safe(() => SampleCpu());
                Safe(SampleMemory);
                Safe(SampleBattery);
                Safe(() => SampleNet());
                Safe(() => SampleProcesses());
                Safe(SampleWifi);
                if ((started - _lastDisk).TotalMinutes >= 5) { _lastDisk = started; Safe(SampleDisks); }
                if ((started - _lastProbe).TotalSeconds >= _o.ProbeSeconds) { _lastProbe = started; await SafeAsync(() => ProbesAsync(ct)); }
                if ((started - _lastNsCheck).TotalMinutes >= 5) { _lastNsCheck = started; await SafeAsync(() => NetskopeStatusAsync(ct)); }
                if ((started - _lastTrace).TotalMinutes >= _o.TraceMinutes) { _lastTrace = started; await SafeAsync(() => TraceAsync(ct)); }
                Samples++;
                var wait = TimeSpan.FromSeconds(_o.IntervalSeconds) - (DateTime.Now - started);
                if (wait > TimeSpan.Zero) await Task.Delay(wait, ct);
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            NetworkChange.NetworkAddressChanged -= OnAddressChanged;
            SystemEvents.PowerModeChanged -= OnPower;
            Event("collector-stop", "");
            lock (_lock) { _w?.Dispose(); _w = null; }
        }
    }

    // ---------------------------------------------------------------- escrita

    private void Write(string k, Dictionary<string, object?> fields)
    {
        var now = DateTimeOffset.Now;
        var o = new Dictionary<string, object?> { ["t"] = now.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz", CultureInfo.InvariantCulture), ["k"] = k };
        foreach (var kv in fields) if (kv.Value != null) o[kv.Key] = kv.Value;
        var line = JsonSerializer.Serialize(o);
        lock (_lock)
        {
            if (_w is null || now.Date != _fileDay)
            {
                _w?.Dispose();
                _fileDay = now.Date;
                CurrentFile = Path.Combine(AppSettings.TelemetryDir, $"nla-telemetry-{_host}-{now:yyyyMMdd}.jsonl");
                var isNew = !File.Exists(CurrentFile);
                _w = new StreamWriter(new FileStream(CurrentFile, FileMode.Append, FileAccess.Write, FileShare.ReadWrite), new UTF8Encoding(false)) { AutoFlush = true };
                if (isNew || k != "meta") _w.WriteLine(JsonSerializer.Serialize(Meta(now)));
            }
            _w.WriteLine(line);
        }
    }

    private Dictionary<string, object?> Meta(DateTimeOffset now)
    {
        var mem = NativeMethods.Memory();
        return new Dictionary<string, object?>
        {
            ["t"] = now.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz", CultureInfo.InvariantCulture), ["k"] = "meta",
            ["host"] = _host, ["os"] = OsName(), ["cpu"] = CpuName(), ["cores"] = _cores, ["ramMb"] = (long)(mem.ullTotalPhys / 1048576),
            ["model"] = Model(), ["collector"] = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3),
            ["interval"] = _o.IntervalSeconds, ["tenant"] = Tenant,
        };
    }

    private void Event(string type, string detail) => Write("event", new() { ["type"] = type, ["detail"] = detail });

    private static void Safe(Action a) { try { a(); } catch (Exception) { } }
    private static async Task SafeAsync(Func<Task> a) { try { await a(); } catch (OperationCanceledException) { throw; } catch (Exception) { } }

    private void Cleanup()
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(AppSettings.TelemetryDir, "nla-telemetry-*.jsonl"))
                if (File.GetLastWriteTime(f) < DateTime.Now.AddDays(-Math.Max(1, _o.RetentionDays))) File.Delete(f);
        }
        catch (Exception) { }
    }

    // ---------------------------------------------------------------- dispositivo

    private void SampleCpu(bool prime = false)
    {
        if (!NativeMethods.GetSystemTimes(out var idle, out var kernel, out var user)) return;
        ulong di = idle.Value - _lastIdle, dk = kernel.Value - _lastKernel, du = user.Value - _lastUser;
        _lastIdle = idle.Value; _lastKernel = kernel.Value; _lastUser = user.Value;
        if (prime) return;
        var total = dk + du; // kernel inclui idle
        if (total == 0) return;
        var busy = 100.0 * (total - di) / total;
        Write("cpu", new() { ["v"] = Math.Round(Math.Clamp(busy, 0, 100), 1) });
    }

    private void SampleMemory()
    {
        var m = NativeMethods.Memory();
        if (m.ullTotalPhys == 0) return;
        var used = 100.0 * (m.ullTotalPhys - m.ullAvailPhys) / m.ullTotalPhys;
        double? commit = m.ullTotalPageFile > 0 ? 100.0 * (m.ullTotalPageFile - m.ullAvailPageFile) / m.ullTotalPageFile : null;
        Write("mem", new()
        {
            ["usedPct"] = Math.Round(used, 1), ["availMb"] = (long)(m.ullAvailPhys / 1048576), ["totalMb"] = (long)(m.ullTotalPhys / 1048576),
            ["commitPct"] = commit is double c ? Math.Round(c, 1) : null,
        });
    }

    private void SampleBattery()
    {
        if (!NativeMethods.GetSystemPowerStatus(out var p) || p.BatteryFlag == 128 || p.BatteryLifePercent == 255) return; // sem bateria
        Write("battery", new() { ["pct"] = (int)p.BatteryLifePercent, ["ac"] = p.ACLineStatus == 1 });
    }

    private void SampleDisks()
    {
        foreach (var d in DriveInfo.GetDrives())
        {
            if (d.DriveType != DriveType.Fixed || !d.IsReady || d.TotalSize == 0) continue;
            Write("disk", new()
            {
                ["d"] = d.Name.TrimEnd('\\'), ["usedPct"] = Math.Round(100.0 * (d.TotalSize - d.TotalFreeSpace) / d.TotalSize, 1),
                ["freeGb"] = Math.Round(d.TotalFreeSpace / 1073741824.0, 1), ["totalGb"] = Math.Round(d.TotalSize / 1073741824.0, 1),
            });
        }
    }

    private void SampleProcesses(bool prime = false)
    {
        var now = DateTime.Now;
        var elapsed = (now - _lastProcAt).TotalSeconds;
        var rows = new List<(string Name, double Cpu, double MemMb)>();
        var seen = new Dictionary<int, (string, TimeSpan)>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                if (p.Id == 0) continue;
                var cpu = p.TotalProcessorTime;
                seen[p.Id] = (p.ProcessName, cpu);
                if (!prime && _lastProc.TryGetValue(p.Id, out var last) && elapsed > 0)
                    rows.Add((p.ProcessName, 100.0 * (cpu - last.Cpu).TotalSeconds / (elapsed * _cores), p.WorkingSet64 / 1048576.0));
            }
            catch (Exception) { /* acesso negado a processos do sistema */ }
            finally { p.Dispose(); }
        }
        _lastProc.Clear();
        foreach (var kv in seen) _lastProc[kv.Key] = kv.Value;
        _lastProcAt = now;
        if (prime || rows.Count == 0) return;
        var agg = rows.GroupBy(r => r.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => (Name: g.Key, Cpu: g.Sum(x => x.Cpu), Mem: g.Sum(x => x.MemMb))).ToList();
        var top = agg.OrderByDescending(x => x.Cpu).Take(5).Concat(agg.OrderByDescending(x => x.Mem).Take(3))
            .DistinctBy(x => x.Name).Select(x => new Dictionary<string, object?> { ["n"] = x.Name, ["cpu"] = Math.Round(Math.Max(0, x.Cpu), 1), ["memMb"] = Math.Round(x.Mem) }).ToList();
        Write("procs", new() { ["top"] = top });
    }

    // ---------------------------------------------------------------- rede

    private static IEnumerable<NetworkInterface> ActiveInterfaces() =>
        NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);

    private static string? DefaultGateway() =>
        ActiveInterfaces().SelectMany(n => n.GetIPProperties().GatewayAddresses).Select(g => g.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))?.ToString();

    private static string DnsServers() =>
        string.Join(",", ActiveInterfaces().SelectMany(n => n.GetIPProperties().DnsAddresses).Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).Distinct());

    private void SampleNet(bool prime = false)
    {
        long rx = 0, tx = 0;
        foreach (var n in ActiveInterfaces())
        {
            try { var s = n.GetIPStatistics(); rx += s.BytesReceived; tx += s.BytesSent; } catch (Exception) { }
        }
        var now = DateTime.Now;
        var gw = DefaultGateway();
        var dns = DnsServers();
        if (!prime)
        {
            var sec = (now - _lastNet).TotalSeconds;
            if (sec > 0 && rx >= _lastRx && tx >= _lastTx)
                Write("net", new() { ["rxKbps"] = Math.Round((rx - _lastRx) * 8 / 1000.0 / sec, 1), ["txKbps"] = Math.Round((tx - _lastTx) * 8 / 1000.0 / sec, 1), ["gateway"] = gw, ["dns"] = dns });
            if (_lastGateway != null && gw != _lastGateway) Event("gateway-change", $"{_lastGateway} → {gw ?? "nenhum"}");
            if (_lastDns != null && dns != _lastDns) Event("dns-change", $"{_lastDns} → {dns}");
        }
        _lastRx = rx; _lastTx = tx; _lastNet = now; _lastGateway = gw; _lastDns = dns;
    }

    private void OnAddressChanged(object? sender, EventArgs e)
    {
        try
        {
            var ips = ActiveInterfaces().SelectMany(n => n.GetIPProperties().UnicastAddresses).Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address.ToString()).Where(a => !a.StartsWith("127.", StringComparison.Ordinal));
            Event("net-change", $"IPs: {string.Join(", ", ips)}; gateway: {DefaultGateway() ?? "nenhum"}");
        }
        catch (Exception) { }
    }

    private void OnPower(object? sender, PowerModeChangedEventArgs e)
    {
        if (e.Mode == PowerModes.Suspend) Event("sleep", "");
        else if (e.Mode == PowerModes.Resume) Event("resume", "");
    }

    private static async Task<string> RunAsync(string file, string args, int timeoutMs, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
        };
        using var p = Process.Start(psi)!;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var outTask = p.StandardOutput.ReadToEndAsync(cts.Token);
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) { try { p.Kill(true); } catch (Exception) { } throw; }
        return await outTask;
    }

    private void SampleWifi()
    {
        if (_hasWifi == false) return;
        // chcp 65001 para receber a saída do netsh em UTF-8 (rótulos com acento em pt-BR)
        var text = RunAsync("cmd.exe", "/d /c chcp 65001 >nul & netsh wlan show interfaces", 8000, CancellationToken.None).GetAwaiter().GetResult();
        if (text.Contains("no wireless interface", StringComparison.OrdinalIgnoreCase) || text.Contains("nenhuma interface sem fio", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Wireless AutoConfig Service", StringComparison.OrdinalIgnoreCase) || text.Contains("wlansvc", StringComparison.OrdinalIgnoreCase))
        {
            _hasWifi = false; return;
        }
        _hasWifi = true;
        var w = SnapshotParsers.Parse("netsh", text, null)?.Wifi;
        if (w is null || string.IsNullOrEmpty(w.Ssid))
        {
            var disconnected = text.Contains("disconnected", StringComparison.OrdinalIgnoreCase) || text.Contains("desconectado", StringComparison.OrdinalIgnoreCase);
            if (disconnected) Write("wifi", new() { ["connected"] = false });
            return;
        }
        // RSSI aproximado a partir da qualidade (fórmula usada pelo próprio Windows: qualidade = 2 * (dBm + 100))
        var rssi = w.RssiDbm ?? (w.SignalPct is double q ? Math.Round(q / 2 - 100) : null);
        Write("wifi", new()
        {
            ["connected"] = true, ["ssid"] = w.Ssid, ["bssid"] = w.Bssid, ["signal"] = w.SignalPct, ["rssi"] = rssi, ["rx"] = w.RxMbps, ["tx"] = w.TxMbps,
            ["ch"] = w.Channel, ["band"] = w.Band, ["radio"] = w.Radio, ["iface"] = w.Interface,
        });
    }

    private async Task ProbesAsync(CancellationToken ct)
    {
        var gw = DefaultGateway();
        if (gw != null) await PingAsync(gw, "Gateway local", ct);
        await PingAsync("8.8.8.8", "Internet (8.8.8.8)", ct);

        var tenant = Tenant;
        if (!string.IsNullOrWhiteSpace(tenant))
        {
            await TcpAsync($"gateway-{tenant}.goskope.com", 443, "POP Internet", ct);
            await DnsAsync($"addon-{tenant}.goskope.com", ct);
        }
        else await DnsAsync("www.microsoft.com", ct);
        await TcpAsync("gateway.npa.goskope.com", 443, "POP Private Access", ct);

        foreach (var url in _o.ProbeUrls.Where(u => Uri.IsWellFormedUriString(u, UriKind.Absolute)).Take(6))
            await HttpAsync(url, ct);
    }

    private readonly Dictionary<string, (bool EverOk, int Rounds)> _pingState = new();

    private async Task PingAsync(string host, string label, CancellationToken ct)
    {
        // alvos que nunca responderam (ICMP bloqueado pela rede) não geram "perda" falsa
        var st = _pingState.GetValueOrDefault(label);
        if (!st.EverOk && st.Rounds >= 3) return;
        using var ping = new Ping();
        var rtts = new List<double>(); var sent = 0;
        for (var i = 0; i < 4; i++)
        {
            sent++;
            try
            {
                var r = await ping.SendPingAsync(host, 2000);
                if (r.Status == IPStatus.Success) rtts.Add(r.RoundtripTime);
            }
            catch (PingException) { }
            await Task.Delay(200, ct);
        }
        _pingState[label] = (st.EverOk || rtts.Count > 0, st.Rounds + 1);
        if (!_pingState[label].EverOk)
        {
            if (st.Rounds + 1 == 3) Event("info", $"{label} não responde a ping (ICMP bloqueado?); medição desativada.");
            return;
        }
        double loss = 100.0 * (sent - rtts.Count) / sent;
        double? jitter = rtts.Count > 1 ? rtts.Zip(rtts.Skip(1), (a, b) => Math.Abs(a - b)).Average() : null;
        Write("ping", new() { ["target"] = host, ["label"] = label, ["rtt"] = rtts.Count > 0 ? Math.Round(rtts.Average(), 1) : null, ["loss"] = Math.Round(loss), ["jitter"] = jitter is double j ? Math.Round(j, 1) : null });
    }

    private async Task TcpAsync(string host, int port, string label, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct);
            var ip = addrs.First(a => a.AddressFamily == AddressFamily.InterNetwork);
            using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(4000);
            sw.Restart();
            await s.ConnectAsync(new IPEndPoint(ip, port), cts.Token);
            Write("tcp", new() { ["target"] = $"{host}:{port}", ["label"] = label, ["ms"] = Math.Round(sw.Elapsed.TotalMilliseconds, 1), ["ok"] = true, ["ip"] = ip.ToString() });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Write("tcp", new() { ["target"] = $"{host}:{port}", ["label"] = label, ["ok"] = false, ["error"] = "timeout" });
        }
        catch (Exception ex) when (ex is SocketException or InvalidOperationException)
        {
            Write("tcp", new() { ["target"] = $"{host}:{port}", ["label"] = label, ["ok"] = false, ["error"] = ex.Message });
        }
    }

    private async Task DnsAsync(string name, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(5000);
            await Dns.GetHostAddressesAsync(name, cts.Token);
            Write("dns", new() { ["name"] = name, ["ms"] = Math.Round(sw.Elapsed.TotalMilliseconds, 1), ["ok"] = true });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { Write("dns", new() { ["name"] = name, ["ok"] = false, ["error"] = "timeout" }); }
        catch (SocketException ex) { Write("dns", new() { ["name"] = name, ["ok"] = false, ["error"] = ex.Message }); }
    }

    private async Task HttpAsync(string url, CancellationToken ct)
    {
        var label = new Uri(url).Host;
        var curl = Path.Combine(Environment.SystemDirectory, "curl.exe");
        if (File.Exists(curl))
        {
            var fmt = "%{http_code} %{time_namelookup} %{time_connect} %{time_appconnect} %{time_starttransfer} %{time_total}";
            var outp = (await RunAsync(curl, $"-s -o NUL -m 20 -w \"{fmt}\" \"{url}\"", 25000, ct)).Trim();
            var p = outp.Split(' ');
            if (p.Length == 6 && int.TryParse(p[0], out var code))
            {
                double S(int i) => double.TryParse(p[i], NumberStyles.Float, CultureInfo.InvariantCulture, out var v) ? v * 1000 : 0;
                double dns = S(1), con = S(2), tls = S(3), ttfb = S(4), total = S(5);
                var ok = code is > 0 and < 500;
                Write("http", new()
                {
                    ["url"] = url, ["label"] = label, ["code"] = code, ["ok"] = ok,
                    ["dns"] = ok ? Math.Round(dns, 1) : null, ["tcp"] = ok ? Math.Round(Math.Max(0, con - dns), 1) : null,
                    ["tls"] = ok && tls > 0 ? Math.Round(Math.Max(0, tls - con), 1) : null,
                    ["ttfb"] = ok ? Math.Round(ttfb, 1) : null, ["total"] = ok ? Math.Round(total, 1) : null,
                });
                return;
            }
        }
        // alternativa sem curl
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        var sw = Stopwatch.StartNew();
        try
        {
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            var ttfb = sw.Elapsed.TotalMilliseconds;
            await resp.Content.ReadAsByteArrayAsync(ct);
            var code = (int)resp.StatusCode;
            Write("http", new() { ["url"] = url, ["label"] = label, ["code"] = code, ["ok"] = code < 500, ["ttfb"] = Math.Round(ttfb, 1), ["total"] = Math.Round(sw.Elapsed.TotalMilliseconds, 1) });
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            Write("http", new() { ["url"] = url, ["label"] = label, ["ok"] = false, ["error"] = ex.Message });
        }
    }

    private async Task TraceAsync(CancellationToken ct)
    {
        var tenant = Tenant;
        var host = string.IsNullOrWhiteSpace(tenant) ? "gateway.npa.goskope.com" : $"gateway-{tenant}.goskope.com";
        IPAddress target;
        try { target = (await Dns.GetHostAddressesAsync(host, ct)).First(a => a.AddressFamily == AddressFamily.InterNetwork); }
        catch (Exception ex) when (ex is SocketException or InvalidOperationException) { return; }
        using var ping = new Ping();
        var hops = new List<Dictionary<string, object?>>();
        var buffer = new byte[32];
        for (var ttl = 1; ttl <= 24; ttl++)
        {
            var sw = Stopwatch.StartNew();
            PingReply? r = null;
            try { r = await ping.SendPingAsync(target, 1500, buffer, new PingOptions(ttl, true)); } catch (PingException) { }
            var ms = Math.Round(sw.Elapsed.TotalMilliseconds, 1);
            if (r is null || r.Status == IPStatus.TimedOut) { hops.Add(new() { ["ttl"] = ttl, ["ip"] = "*" }); continue; }
            hops.Add(new() { ["ttl"] = ttl, ["ip"] = r.Address?.ToString(), ["rtt"] = r.Status == IPStatus.Success && r.RoundtripTime > 0 ? r.RoundtripTime : ms });
            if (r.Status == IPStatus.Success) break;
        }
        Write("trace", new() { ["target"] = host, ["hops"] = hops });
    }

    private async Task NetskopeStatusAsync(CancellationToken ct)
    {
        var nsdiag = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Netskope", "STAgent", "nsdiag.exe");
        if (!File.Exists(nsdiag)) return;
        var outp = await RunAsync(nsdiag, "-f", 15000, ct);
        var lines = outp.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && (l.Contains("status", StringComparison.OrdinalIgnoreCase) || l.Contains("Gateway", StringComparison.OrdinalIgnoreCase) || l.Contains("tunnel", StringComparison.OrdinalIgnoreCase))).Take(8);
        var summary = string.Join("; ", lines);
        if (summary.Length > 300) summary = summary[..300];
        if (summary.Length > 0 && summary != _lastNs) Event("nsclient", summary);
        _lastNs = summary;
    }

    // ---------------------------------------------------------------- informações estáticas

    private static string OsName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var name = k?.GetValue("ProductName") as string ?? "Windows";
            var build = k?.GetValue("CurrentBuild") as string;
            var disp = k?.GetValue("DisplayVersion") as string;
            if (int.TryParse(build, out var b) && b >= 22000) name = name.Replace("Windows 10", "Windows 11");
            return $"{name} {disp} (build {build})".Replace("  ", " ");
        }
        catch (Exception) { return Environment.OSVersion.VersionString; }
    }

    private static string? CpuName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return (k?.GetValue("ProcessorNameString") as string)?.Trim();
        }
        catch (Exception) { return null; }
    }

    private static string? Model()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\BIOS");
            var make = k?.GetValue("SystemManufacturer") as string; var model = k?.GetValue("SystemProductName") as string;
            return $"{make} {model}".Trim();
        }
        catch (Exception) { return null; }
    }

    public void Dispose() { lock (_lock) { _w?.Dispose(); _w = null; } }

    // ---------------------------------------------------------------- controle do coletor em segundo plano

    public static bool IsRunning() => Mutex.TryOpenExisting(MutexName, out var m) && DisposeTrue(m);
    private static bool DisposeTrue(Mutex m) { m.Dispose(); return true; }

    /// <summary>Inicia o coletor em segundo plano (processo separado, sem janela).</summary>
    public static void StartBackground()
    {
        if (IsRunning()) return;
        var exe = Environment.ProcessPath!;
        Process.Start(new ProcessStartInfo(exe, "--collect") { UseShellExecute = false, CreateNoWindow = true });
    }

    public static void StopBackground()
    {
        if (EventWaitHandle.TryOpenExisting(StopEventName, out var ev)) using (ev) ev.Set();
    }

    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValue = "NetskopeLogAnalyzerCollector";

    /// <summary>Coleta contínua: inicia o coletor automaticamente no logon do usuário.</summary>
    public static bool AutoStartEnabled
    {
        get { using var k = Registry.CurrentUser.OpenSubKey(RunKey); return k?.GetValue(RunValue) != null; }
        set
        {
            using var k = Registry.CurrentUser.CreateSubKey(RunKey);
            if (value) k.SetValue(RunValue, $"\"{Environment.ProcessPath}\" --collect");
            else k.DeleteValue(RunValue, false);
        }
    }

    public static IEnumerable<string> LocalTelemetryFiles(int days = 14)
    {
        if (!Directory.Exists(AppSettings.TelemetryDir)) return Enumerable.Empty<string>();
        return Directory.EnumerateFiles(AppSettings.TelemetryDir, "nla-telemetry-*.jsonl")
            .Where(f => File.GetLastWriteTime(f) >= DateTime.Now.AddDays(-days)).OrderBy(f => f);
    }
}
