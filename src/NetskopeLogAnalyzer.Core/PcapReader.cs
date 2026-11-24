using System.Buffers.Binary;
using System.Net;

namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Resumo de capturas .pcap/.pcapng sem depender do Wireshark: pacotes, fluxos TCP, retransmissões,
/// RST, janela zero, handshakes sem resposta, códigos de resposta DNS, alertas TLS e principais destinos.
/// Suporta Ethernet, Linux SLL/SLL2, IP puro (túneis), loopback/NULL, IPv4 e IPv6.
/// </summary>
public static class PcapReader
{
    private const int MaxSeqPerFlow = 50000;

    public static bool LooksLikeCapture(string name, byte[] d) =>
        d.Length >= 24 && (IsPcap(d) || IsPcapNg(d)) || name.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase);

    private static bool IsPcap(byte[] d)
    {
        var m = BinaryPrimitives.ReadUInt32LittleEndian(d);
        return m is 0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1;
    }

    private static bool IsPcapNg(byte[] d) => BinaryPrimitives.ReadUInt32LittleEndian(d) == 0x0A0D0D0A;

    private sealed class State
    {
        public required CaptureSummary S;
        public readonly Dictionary<string, HashSet<(uint, int)>> Seqs = new();
        public readonly HashSet<string> SynFlows = new(), SynAckFlows = new(), Flows = new();
        public readonly Dictionary<string, long> DestBytes = new(), RetransDest = new();
    }

    public static CaptureSummary Read(string name, byte[] d)
    {
        var st = new State { S = new CaptureSummary { File = name } };
        try
        {
            if (d.Length < 24) { st.S.Error = "arquivo vazio ou truncado"; return st.S; }
            if (IsPcap(d)) ReadPcap(d, st);
            else if (IsPcapNg(d)) ReadPcapNg(d, st);
            else st.S.Error = "formato de captura não reconhecido";
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or OverflowException)
        {
            st.S.Error ??= "captura truncada (resumo parcial)";
        }
        var s = st.S;
        s.TcpFlows = st.Flows.Count;
        s.HandshakeFailures = st.SynFlows.Count(f => !st.SynAckFlows.Contains(f));
        s.TopDestinations.AddRange(st.DestBytes.OrderByDescending(kv => kv.Value).Take(10));
        s.TopRetransDestinations.AddRange(st.RetransDest.OrderByDescending(kv => kv.Value).Take(10));
        return s;
    }

    private static void ReadPcap(byte[] d, State st)
    {
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(d);
        var le = magic is 0xa1b2c3d4 or 0xa1b23c4d;
        var nano = magic is 0xa1b23c4d or 0x4d3cb2a1;
        uint U32(int o) => le ? BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o)) : BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(o));
        var link = (int)(U32(20) & 0x0FFFFFFF);
        st.S.LinkType = LinkName(link);
        var off = 24;
        while (off + 16 <= d.Length)
        {
            var sec = U32(off); var frac = U32(off + 4); var incl = (int)U32(off + 8); var orig = U32(off + 12);
            off += 16;
            if (incl < 0 || off + incl > d.Length) { st.S.Error = "captura truncada (resumo parcial)"; break; }
            var t = DateTimeOffset.FromUnixTimeSeconds(sec).AddTicks(nano ? frac / 100 : frac * 10L).LocalDateTime;
            Packet(st, link, d.AsSpan(off, incl), t, orig);
            off += incl;
        }
    }

    private static void ReadPcapNg(byte[] d, State st)
    {
        var le = true;
        var links = new List<(int Link, double Res)>();
        var off = 0;
        while (off + 12 <= d.Length)
        {
            var type = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(off));
            if (type == 0x0A0D0D0A)
            {
                var bom = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(off + 8));
                le = bom == 0x1A2B3C4D;
                links.Clear();
            }
            uint U32(int o) => le ? BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o)) : BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(o));
            ushort U16(int o) => le ? BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(o)) : BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(o));
            type = U32(off);
            var len = (int)U32(off + 4);
            if (len < 12 || off + len > d.Length) { st.S.Error = "captura truncada (resumo parcial)"; break; }
            if (type == 1) // Interface Description Block
            {
                var link = U16(off + 8);
                var res = 1e-6;
                var o = off + 16;
                while (o + 4 <= off + len - 4)
                {
                    var code = U16(o); var olen = U16(o + 2);
                    if (code == 0) break;
                    if (code == 9 && olen >= 1)
                    {
                        var v = d[o + 4];
                        res = (v & 0x80) != 0 ? Math.Pow(2, -(v & 0x7F)) : Math.Pow(10, -v);
                    }
                    o += 4 + ((olen + 3) & ~3);
                }
                links.Add((link, res));
                if (st.S.LinkType.Length == 0) st.S.LinkType = LinkName(link);
            }
            else if (type == 6 && len >= 32) // Enhanced Packet Block
            {
                var ifc = (int)U32(off + 8);
                var ts = ((ulong)U32(off + 12) << 32) | U32(off + 16);
                var cap = (int)U32(off + 20); var orig = U32(off + 24);
                var (link, res) = ifc < links.Count ? links[ifc] : (1, 1e-6);
                if (cap >= 0 && off + 28 + cap <= off + len)
                {
                    var secs = ts * res;
                    var t = DateTime.UnixEpoch.AddTicks((long)(secs * TimeSpan.TicksPerSecond)).ToLocalTime();
                    Packet(st, link, d.AsSpan(off + 28, cap), t, orig);
                }
            }
            else if (type == 3 && len >= 16) // Simple Packet Block
            {
                var orig = U32(off + 8);
                var cap = Math.Min((int)orig, len - 16);
                var link = links.Count > 0 ? links[0].Link : 1;
                Packet(st, link, d.AsSpan(off + 12, Math.Max(0, cap)), null, orig);
            }
            off += len;
        }
    }

    private static string LinkName(int l) => l switch
    {
        0 => "loopback (NULL)", 1 => "Ethernet", 12 or 14 or 101 => "IP (túnel/raw)", 108 => "loopback", 113 => "Linux SLL", 276 => "Linux SLL2",
        228 => "IPv4", 229 => "IPv6", _ => "tipo " + l,
    };

    private static void Packet(State st, int link, ReadOnlySpan<byte> p, DateTime? t, uint orig)
    {
        var s = st.S;
        s.Packets++;
        s.Bytes += orig;
        if (t is DateTime tt)
        {
            if (s.First is null || tt < s.First) s.First = tt;
            if (s.Last is null || tt > s.Last) s.Last = tt;
        }
        int ipOff; ushort eth = 0;
        switch (link)
        {
            case 1:
                if (p.Length < 14) return;
                eth = BinaryPrimitives.ReadUInt16BigEndian(p[12..]); ipOff = 14;
                while (eth is 0x8100 or 0x88A8 && p.Length >= ipOff + 4) { eth = BinaryPrimitives.ReadUInt16BigEndian(p[(ipOff + 2)..]); ipOff += 4; }
                if (eth != 0x0800 && eth != 0x86DD) return;
                break;
            case 113: if (p.Length < 16) return; ipOff = 16; break;
            case 276: if (p.Length < 20) return; ipOff = 20; break;
            case 0 or 108: if (p.Length < 4) return; ipOff = 4; break;
            default: ipOff = 0; break;
        }
        if (p.Length <= ipOff) return;
        var ip = p[ipOff..];
        var ver = ip[0] >> 4;
        string src, dst; int proto; ReadOnlySpan<byte> l4; int l4Len;
        if (ver == 4)
        {
            if (ip.Length < 20) return;
            var ihl = (ip[0] & 0x0F) * 4;
            var total = BinaryPrimitives.ReadUInt16BigEndian(ip[2..]);
            proto = ip[9];
            src = new IPAddress(ip.Slice(12, 4)).ToString();
            dst = new IPAddress(ip.Slice(16, 4)).ToString();
            if (ihl < 20 || ip.Length < ihl) return;
            l4 = ip[ihl..];
            l4Len = Math.Max(0, (total > 0 ? total : ip.Length) - ihl);
            var fragOff = BinaryPrimitives.ReadUInt16BigEndian(ip[6..]) & 0x1FFF;
            if (fragOff != 0) return;
        }
        else if (ver == 6)
        {
            if (ip.Length < 40) return;
            var plen = BinaryPrimitives.ReadUInt16BigEndian(ip[4..]);
            proto = ip[6];
            src = new IPAddress(ip.Slice(8, 16)).ToString();
            dst = new IPAddress(ip.Slice(24, 16)).ToString();
            var o = 40;
            while (proto is 0 or 43 or 60 && ip.Length >= o + 8)
            {
                var extLen = (ip[o + 1] + 1) * 8;
                proto = ip[o];
                o += extLen;
                plen = (ushort)Math.Max(0, plen - extLen);
            }
            if (ip.Length < o) return;
            l4 = ip[o..];
            l4Len = plen;
        }
        else return;

        if (proto == 6 && l4.Length >= 20) Tcp(st, src, dst, l4, l4Len);
        else if (proto == 17 && l4.Length >= 8)
        {
            s.Udp++;
            var sp = BinaryPrimitives.ReadUInt16BigEndian(l4); var dp = BinaryPrimitives.ReadUInt16BigEndian(l4[2..]);
            if (sp == 53 && l4.Length >= 12 && (l4[10] & 0x80) != 0)
            {
                var rc = (l4[11] & 0x0F) switch { 0 => "NOERROR", 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED", var x => "RCODE " + x };
                s.DnsRcodes[rc] = s.DnsRcodes.GetValueOrDefault(rc) + 1;
            }
            var server = sp < dp ? $"{src}:{sp}/udp" : $"{dst}:{dp}/udp";
            st.DestBytes[server] = st.DestBytes.GetValueOrDefault(server) + l4Len;
        }
    }

    private static void Tcp(State st, string src, string dst, ReadOnlySpan<byte> t, int segLen)
    {
        var s = st.S;
        var sp = BinaryPrimitives.ReadUInt16BigEndian(t); var dp = BinaryPrimitives.ReadUInt16BigEndian(t[2..]);
        var seq = BinaryPrimitives.ReadUInt32BigEndian(t[4..]);
        var hl = (t[12] >> 4) * 4;
        var flags = t[13];
        var win = BinaryPrimitives.ReadUInt16BigEndian(t[14..]);
        bool syn = (flags & 0x02) != 0, ack = (flags & 0x10) != 0, rst = (flags & 0x04) != 0, fin = (flags & 0x01) != 0;
        var payload = Math.Max(0, segLen - hl);
        var dir = $"{src}:{sp}>{dst}:{dp}";
        var canon = string.CompareOrdinal($"{src}:{sp}", $"{dst}:{dp}") < 0 ? $"{src}:{sp}|{dst}:{dp}" : $"{dst}:{dp}|{src}:{sp}";
        var server = sp < dp ? $"{src}:{sp}" : $"{dst}:{dp}";
        st.Flows.Add(canon);
        st.DestBytes[server] = st.DestBytes.GetValueOrDefault(server) + segLen;
        if (syn && !ack) { s.Syn++; st.SynFlows.Add(canon); }
        if (syn && ack) { s.SynAck++; st.SynAckFlows.Add(canon); }
        if (rst) s.Resets++;
        if (win == 0 && !rst && !syn && !fin) s.ZeroWindow++;
        if (payload > 0)
        {
            s.TcpDataSegments++;
            if (!st.Seqs.TryGetValue(dir, out var set)) { set = new HashSet<(uint, int)>(); st.Seqs[dir] = set; }
            if (set.Contains((seq, payload)))
            {
                s.Retransmissions++;
                st.RetransDest[server] = st.RetransDest.GetValueOrDefault(server) + 1;
            }
            else if (set.Count < MaxSeqPerFlow) set.Add((seq, payload));
            if (hl >= 20 && t.Length > hl + 1 && t[hl] == 0x15 && t[hl + 1] == 0x03) s.TlsAlerts++;
        }
    }
}
