# Netskope Log Analyzer

Ferramenta para analisar o pacote de logs do **Netskope Client** (o `.zip` gerado por *Save logs* ou `nsdiag -o`). Basta importar o arquivo: o app identifica falhas e erros conhecidos, separa o que é ruído e mostra **como resolver** cada problema, com comandos prontos e links para a documentação oficial da Netskope.

> A análise roda 100% localmente, no navegador. Nenhum log sai do computador. Isso importa porque o pacote contém token, número de série, e-mails e hostnames.

## O que o app mostra

- **Resumo**: veredito (crítico / atenção / ok), estado final dos túneis Internet (SWG) e Private Access (NPA), versão do cliente, tenant, steering, se o dispositivo está on-prem ou off-prem, IP de saída, POP, DNS e fail-close.
- **Linha do tempo**: início e parada do serviço, registro (enroll), túnel conectado ou derrubado, desativação pelo usuário e mudança de localização, mais um gráfico de erros por minuto.
- **Diagnóstico**: cerca de 40 padrões conhecidos, classificados em Crítico, Atenção, Informativo ou Ruído conhecido. Cada item traz:
  - o que significa;
  - **como resolver**, passo a passo, com comandos para o sistema detectado (Linux, Windows ou macOS), já preenchidos com o tenant e as interfaces do log;
  - links da documentação oficial (docs.netskope.com e community.netskope.com);
  - botões de pesquisa na documentação, na comunidade e na base de conhecimento do suporte.
- **Detecções de ambiente**: VPNs de terceiros em execução (FortiClient, Zscaler, GlobalProtect, AnyConnect…), interfaces de VPN órfãs com DNS internos, dependências ausentes e versão divergente.
- **Erros não classificados**: erros e alertas sem padrão conhecido, agrupados e normalizados.
- **Explorador de logs**: busca por texto com filtro por nível e por arquivo.
- **Copiar relatório**: resumo em Markdown, com os passos de resolução, pronto para colar num chamado.

Formatos lidos: `nsdebuglog.log`, `npadebuglog.log`, `nsApp.log`, `nsAppUI.log`, `nsInstallation.log`, `nsDiag-*.log`, `install.log`, `network-state.log`, `appInfo.log` e os JSON de configuração (`nsconfig.json`, `eventcache.json`, `nsuser.conf`, `nssteering.json`). ZIPs aninhados e ZIP64 também são suportados.

## Instalação (Windows 10/11)

Baixe o instalador na página de [Releases](../../releases).

**Recomendado: `NetskopeLogAnalyzer-<versão>-Setup.exe`**
1. Execute o Setup. Não precisa de administrador: a instalação é por usuário, em `%LOCALAPPDATA%\Programs\NetskopeLogAnalyzer`.
2. Se o SmartScreen avisar (o instalador não é assinado digitalmente), clique em *Mais informações* > *Executar assim mesmo*.
3. O app ganha atalho no Menu Iniciar (e, se quiser, na Área de Trabalho) e abre em janela própria, usando o Microsoft Edge em modo aplicativo.

Para desinstalar: *Configurações > Aplicativos > Aplicativos instalados > Netskope Log Analyzer*.

**Alternativas**
- `NetskopeLogAnalyzer-<versão>-Windows.zip`: extraia e execute `Instalar.cmd` (instalador por PowerShell, para ambientes que bloqueiam `.exe`).
- `NetskopeLogAnalyzer-<versão>-portatil.html`: abre direto no Edge ou Chrome, sem instalar.

O app roda no Windows, mas analisa pacotes de logs do Netskope Client vindos de Windows, macOS e Linux.

## Desenvolvimento

```
src/index.html                  aplicativo (HTML/CSS/JS em um único arquivo, sem dependências)
assets/                         ícones (SVG, PNG, ICO)
installer/NetskopeLogAnalyzer.iss  script do instalador (Inno Setup 6)
packaging/windows/              instalador alternativo por PowerShell e LEIA-ME
build.ps1                       gera os pacotes em dist\
.github/workflows/release.yml   compila e publica a release quando VERSION muda na main
VERSION                         versão atual
```

Gerar os pacotes localmente (o Setup.exe requer o [Inno Setup 6](https://jrsoftware.org/isinfo.php)):
```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

Publicar uma nova versão: atualize `VERSION` (ex.: `1.0.1`) e `RELEASE_NOTES.md`, faça commit e push na `main`. O GitHub Actions compila o instalador num runner Windows e cria a release `v1.0.1` com os pacotes anexados. Também dá para disparar manualmente em *Actions > Build e Release (Windows) > Run workflow*, ou criando uma tag `v*`.

### Adicionar um novo padrão de erro
Em `src/index.html`:
1. Adicione uma entrada em `RULES` com `id`, `re` (regex aplicada à mensagem), `sev` (`crit` | `warn` | `info` | `noise`) ou `sevf` (severidade por contagem), `cat`, `t` (título) e `w` (o que significa).
2. Adicione a resolução em `FIX[id]`: `fx` com passos `[texto, comando]` por sistema (`all`, `linux`, `windows`, `mac`, `end`), `refs` (chaves de `REF`) e `kq` (termos de pesquisa).

Nos comandos, `{NSD}` vira o caminho do `nsdiag` do sistema detectado e `{T}` vira o tenant extraído do log.

## Aviso

**Nunca faça commit de pacotes de logs reais neste repositório.** O `.gitignore` já bloqueia `NetskopeLogs*.zip` e `*.log`.

As resoluções foram montadas a partir da documentação pública da Netskope (nov/2026) e não substituem o suporte oficial.
