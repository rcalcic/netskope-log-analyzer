# Liberação do Netskope Log Analyzer pelo TI

Os executáveis do Netskope Log Analyzer **não têm assinatura digital**. Por isso o Windows pode bloqueá-los até que o TI os libere. Este guia reúne o que é preciso para liberar e distribuir o app.

## O que o app faz (para a análise de segurança)

- Aplicativo desktop nativo (.NET 8 / WPF), executável único e autocontido. Não instala drivers, serviços do Windows, tarefas agendadas nem extensões.
- Lê pacotes de log (.zip) escolhidos pelo analista e analisa tudo localmente. Nenhum log é enviado para fora da máquina. Não coleta dados da máquina, não executa comandos de diagnóstico e não instala nada além do próprio app.
- **Conexões de rede** (todas HTTPS, iniciadas pelo app):
  - Verificação de atualização: `api.github.com` (última release) e, ao atualizar, `github.com` e `objects.githubusercontent.com` / `release-assets.githubusercontent.com` (download do Setup e do `SHA256SUMS.txt`). Desativável por política.
  - Links da documentação só abrem no navegador padrão quando o usuário clica.
- **Atualização:** baixa o Setup da release, confere o SHA-256 com o `SHA256SUMS.txt` e só então executa a instalação silenciosa (pede elevação se o app estiver instalado por máquina).
- Instalação: `C:\Program Files\Netskope Log Analyzer\NetskopeLogAnalyzer.exe`, atalho no Menu Iniciar e entrada em *Abrir com* para `.zip` e `.log` (chaves em `Software\Classes\Applications\NetskopeLogAnalyzer.exe`).
- **Entrada não confiável:** o pacote é lido só em memória (nenhum arquivo do `.zip` é gravado em disco, sem risco de *zip slip*), com limites de tamanho (512 MB por arquivo, 3 GB no total), 20.000 entradas, 3 níveis de `.zip` aninhados, detecção de *zip bomb*, linhas truncadas em 16 KB, tempo máximo de 2 s em expressões regulares e limites no leitor de `.pcap`. Valores do log são saneados antes de aparecer em comandos sugeridos; o app nunca executa esses comandos.
- Código-fonte: https://github.com/rcalcic/netskope-log-analyzer — os pacotes são compilados pelo GitHub Actions a partir desse código.

## Hashes

Cada release publica `SHA256SUMS.txt` e lista os hashes nas notas da release. Libere por **hash** (não há editor/certificado para regra de publicador):

- `NetskopeLogAnalyzer.exe` — o executável instalado (mesmo arquivo do pacote portátil);
- `NetskopeLogAnalyzer-<versão>-Setup.exe` — o instalador;

Cada nova versão tem hashes novos e precisa ser liberada de novo.

Conferir um hash no Windows:
```powershell
Get-FileHash .\NetskopeLogAnalyzer-4.0.0-Setup.exe -Algorithm SHA256
```

## Instalação silenciosa (Intune, SCCM, GPO)

```cmd
NetskopeLogAnalyzer-<versão>-Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /ALLUSERS
```
Desinstalação:
```cmd
"C:\Program Files\Netskope Log Analyzer\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```
Regra de detecção (Intune Win32): arquivo `C:\Program Files\Netskope Log Analyzer\NetskopeLogAnalyzer.exe`, versão do arquivo ≥ `<versão>`.

## Políticas (GPO / Intune)

Chave `HKLM\Software\Policies\NetskopeLogAnalyzer`:

| Valor | Tipo | Efeito |
|---|---|---|
| `DisableUpdates` | DWORD `1` | Desliga a verificação e a instalação de atualizações (use quando o TI distribui as versões). |
| `UpdateFeedUrl` | String | URL alternativa no formato da API de releases do GitHub (ex.: espelho interno). |

```cmd
reg add "HKLM\Software\Policies\NetskopeLogAnalyzer" /v DisableUpdates /t REG_DWORD /d 1 /f
```

Com o tráfego passando pelo Netskope, libere no steering/SSL as URLs de atualização acima se elas forem bloqueadas.

## Por mecanismo de bloqueio

**Microsoft Defender SmartScreen** — aparece “O Windows protegeu o computador”.
- Usuário: *Mais informações* > *Executar assim mesmo* (se a política permitir).
- TI: com Defender for Endpoint, crie um **indicador de arquivo** (*Allow*) com o SHA-256 do Setup e do `.exe`.

**AppLocker** — as regras padrão já permitem executáveis em `Program Files`; instale com o Setup (por máquina) ou crie uma **regra de hash de arquivo** para o `.exe`.

**App Control for Business (WDAC)** — adicione regras de hash para os dois arquivos na política (ex.: `New-CIPolicyRule -Level Hash -DriverFilePath <arquivo>`), ou use uma política suplementar.

**Controle Inteligente de Aplicativos (Smart App Control, Windows 11)** — **não aceita exceções por app**: bloqueia qualquer executável sem assinatura e sem reputação. As únicas saídas são assinar o executável (certificado de assinatura de código da empresa ou Azure Artifact Signing) ou desativar o recurso no dispositivo (*Segurança do Windows > Controle de aplicativos e navegador*; a reativação exige reinstalar o Windows). Em dispositivos gerenciados normalmente ele já vem desativado.

## Assinatura (opcional, recomendada no futuro)

Com um certificado de assinatura de código (`.pfx` da PKI da empresa ou Azure Artifact Signing), o workflow pode assinar o `.exe` e o `Setup.exe` antes de publicar. Assim a liberação passa a ser por **editor**, válida para todas as versões futuras.
