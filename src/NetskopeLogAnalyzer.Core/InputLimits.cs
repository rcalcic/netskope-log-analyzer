using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;

namespace NetskopeLogAnalyzer.Core;

/// <summary>
/// Limites de segurança para pacotes recebidos de terceiros (podem ser maliciosos ou corrompidos):
/// zip bomb, zips aninhados em profundidade, arquivos gigantes, excesso de entradas e expressões
/// regulares lentas (ReDoS). Valores folgados para pacotes reais do Netskope (dezenas de MB).
/// </summary>
public static class InputLimits
{
    public const long MaxFileBytes = 1L * 1024 * 1024 * 1024;           // 1 GB por arquivo lido do disco
    public const long MaxEntryBytes = 512L * 1024 * 1024;               // 512 MB por arquivo dentro do zip
    public const long MaxTotalUncompressed = 3L * 1024 * 1024 * 1024;   // 3 GB por análise
    public const int MaxZipEntries = 20000;
    public const int MaxZipDepth = 3;
    public const double MaxCompressionRatio = 250;                       // acima disso (e > 50 MB) = zip bomb
    public const int MaxFolderFiles = 20000;
    public const int MaxEntries = 8_000_000;                             // linhas de log mantidas em memória
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(2);

    /// <summary>Tempo máximo padrão para qualquer Regex do processo: uma linha maliciosa não trava a análise.</summary>
    [ModuleInitializer]
    internal static void Init()
    {
        try { AppContext.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", RegexTimeout); } catch (Exception) { }
    }

    /// <summary>Copia no máximo <paramref name="max"/> bytes; retorna null se passar do limite.</summary>
    public static byte[]? ReadBounded(Stream s, long max)
    {
        using var ms = new MemoryStream();
        var buf = new byte[81920];
        long total = 0; int n;
        while ((n = s.Read(buf, 0, buf.Length)) > 0)
        {
            total += n;
            if (total > max) return null;
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }
}

/// <summary>
/// Valores vindos dos logs inseridos em comandos sugeridos ao analista. Um log forjado poderia trazer,
/// por exemplo, um "nome de interface" com ";" ou "$( )" e induzir o analista a executar um comando
/// malicioso ao copiar. Só passam identificadores simples; o resto vira um marcador para preencher.
/// </summary>
public static class SafeText
{
    private static readonly Regex TokenRe = new(@"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,62}$", RegexOptions.CultureInvariant);
    private static readonly Regex HostRe = new(@"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.){0,10}[A-Za-z0-9-]{1,63}$", RegexOptions.CultureInvariant);

    public static string Token(string? value, string placeholder) => value != null && TokenRe.IsMatch(value) ? value : placeholder;

    public static string Host(string? value, string placeholder) =>
        value != null && (HostRe.IsMatch(value) || System.Net.IPAddress.TryParse(value, out _)) && value.Length <= 253 ? value : placeholder;

    /// <summary>Remove caracteres de controle (exceto quebra de linha/tab) para exibir texto de log com segurança.</summary>
    public static string Printable(string s)
    {
        if (s.Length == 0) return s;
        var sb = new System.Text.StringBuilder(s.Length);
        foreach (var c in s) sb.Append(char.IsControl(c) && c is not ('\n' or '\t') ? ' ' : c is '‮' or '‭' or '⁦' or '⁧' or '⁨' or '⁩' ? ' ' : c);
        return sb.ToString();
    }
}
