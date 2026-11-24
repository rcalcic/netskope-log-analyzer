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

### Recomendado: instalar pelo Microsoft Edge (sem executável)
1. Abra **https://rcalcic.github.io/netskope-log-analyzer/** no Microsoft Edge (ou Chrome).
2. Clique no botão **Instalar app** no topo da página, ou no ícone *Aplicativo disponível* na barra de endereços, e confirme.
3. Pronto: o **Netskope Log Analyzer** aparece no Menu Iniciar, abre em janela própria, funciona offline e pode ser fixado na barra de tarefas.

Esse método não executa nenhum `.exe`, por isso o SmartScreen, o Controle Inteligente de Aplicativos e políticas que bloqueiam executáveis sem assinatura não interferem. Os logs continuam sendo analisados só no computador: o site é apenas o código do app e nada é enviado.

Para desinstalar: abra o app, clique em *…* no canto da janela > *Desinstalar*, ou use *Configurações > Aplicativos > Aplicativos instalados*.

Depois de instalado, dá para abrir um `.zip` de logs direto pelo Explorador de Arquivos com *Abrir com > Netskope Log Analyzer*.

### Alternativas (baixe na página de [Releases](../../releases))
- `NetskopeLogAnalyzer-<versão>-Setup.exe`: instalador clássico. Como **não tem assinatura digital**, o Windows pode bloquear; se aparecer “O Windows protegeu o computador”, clique em *Mais informações* > *Executar assim mesmo*. Se não houver essa opção (Controle Inteligente de Aplicativos ativo ou política corporativa), use o método pelo Edge.
- `NetskopeLogAnalyzer-<versão>-Windows.zip`: instalador por PowerShell (`Instalar.cmd`).
- `NetskopeLogAnalyzer-<versão>-portatil.html`: abre direto no navegador, sem instalar.

O app roda no Windows, mas analisa pacotes de logs do Netskope Client vindos de Windows, macOS e Linux.

## Desenvolvimento

```
src/index.html                  aplicativo (HTML/CSS/JS em um único arquivo, sem dependências)
assets/                         ícones (SVG, PNG, ICO)
installer/NetskopeLogAnalyzer.iss  script do instalador (Inno Setup 6)
packaging/windows/              instalador alternativo por PowerShell e LEIA-ME
web/                            manifesto e service worker do app instalável (PWA)
tools/build_site.py             gera o site do GitHub Pages em site/
build.ps1                       gera Setup.exe, zip e versão portátil em dist\
.github/workflows/release.yml   compila e publica a release quando VERSION muda na main
.github/workflows/pages.yml     publica o app no GitHub Pages a cada mudança na main
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
