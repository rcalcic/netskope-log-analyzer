# Liberação do Netskope Log Analyzer pelo TI

Os executáveis do Netskope Log Analyzer **não têm assinatura digital**. Por isso o Windows pode bloqueá-los até que o TI os libere. Este guia reúne o que é preciso para liberar e distribuir o app.

## O que o app faz (para a análise de segurança)

- Aplicativo desktop nativo (.NET 8 / WPF), executável único e autocontido. Não instala drivers, serviços, tarefas agendadas nem extensões.
- Lê arquivos de log escolhidos pelo usuário e analisa tudo em memória. **Não faz conexões de rede.** Links da documentação só são abertos no navegador padrão quando o usuário clica neles.
- Instalação: `C:\Program Files\Netskope Log Analyzer\NetskopeLogAnalyzer.exe`, atalho no Menu Iniciar e entrada em *Abrir com* para `.zip` e `.log` (chaves em `Software\Classes\Applications\NetskopeLogAnalyzer.exe`).
- Código-fonte: https://github.com/rcalcic/netskope-log-analyzer — os pacotes são compilados pelo GitHub Actions a partir desse código.

## Hashes

Cada release publica `SHA256SUMS.txt` e lista os hashes nas notas da release. Libere por **hash** (não há editor/certificado para regra de publicador):

- `NetskopeLogAnalyzer.exe` — o executável instalado (mesmo arquivo do pacote portátil);
- `NetskopeLogAnalyzer-<versão>-Setup.exe` — o instalador.

Cada nova versão tem hashes novos e precisa ser liberada de novo.

Conferir um hash no Windows:
```powershell
Get-FileHash .\NetskopeLogAnalyzer-2.0.0-Setup.exe -Algorithm SHA256
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

## Por mecanismo de bloqueio

**Microsoft Defender SmartScreen** — aparece “O Windows protegeu o computador”.
- Usuário: *Mais informações* > *Executar assim mesmo* (se a política permitir).
- TI: com Defender for Endpoint, crie um **indicador de arquivo** (*Allow*) com o SHA-256 do Setup e do `.exe`.

**AppLocker** — as regras padrão já permitem executáveis em `Program Files`; instale com o Setup (por máquina) ou crie uma **regra de hash de arquivo** para o `.exe`.

**App Control for Business (WDAC)** — adicione regras de hash para os dois arquivos na política (ex.: `New-CIPolicyRule -Level Hash -DriverFilePath <arquivo>`), ou use uma política suplementar.

**Controle Inteligente de Aplicativos (Smart App Control, Windows 11)** — **não aceita exceções por app**: bloqueia qualquer executável sem assinatura e sem reputação. As únicas saídas são assinar o executável (certificado de assinatura de código da empresa ou Azure Artifact Signing) ou desativar o recurso no dispositivo (*Segurança do Windows > Controle de aplicativos e navegador*; a reativação exige reinstalar o Windows). Em dispositivos gerenciados normalmente ele já vem desativado.

## Assinatura (opcional, recomendada no futuro)

Com um certificado de assinatura de código (`.pfx` da PKI da empresa ou Azure Artifact Signing), o workflow pode assinar o `.exe` e o `Setup.exe` antes de publicar. Assim a liberação passa a ser por **editor**, válida para todas as versões futuras.
