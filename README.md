# Netskope Log Analyzer

Aplicativo **nativo para Windows** (C#/.NET 8, WPF) que analisa o pacote de logs do **Netskope Client** — o `.zip` gerado por *Save logs* ou `nsdiag -o`. Basta abrir o arquivo: o app identifica falhas e erros conhecidos, separa o que é ruído e mostra **como resolver** cada problema, com comandos prontos e links para a documentação oficial da Netskope.

- **Sem navegador:** não usa Edge, Chrome, WebView2 nem nenhum motor web.
- **Sem dependências:** um único `.exe` autocontido; não precisa nem do .NET instalado.
- **Privado:** a análise roda inteiramente no computador. Nenhum log é enviado — o pacote contém token, número de série, e-mails e hostnames. A única ação de rede é abrir um link da documentação no seu navegador padrão, e só quando você clica nele.

## O que o app mostra

| Aba | Conteúdo |
|---|---|
| **Resumo** | Veredito (crítico / atenção / ok), estado final dos túneis Internet (SWG) e Private Access (NPA), versão do cliente, tenant, steering, on-prem/off-prem, IP de saída, POP, DNS, fail-close e principais pontos. |
| **Linha do tempo** | Início e parada do serviço, registro (enroll), túnel conectado/derrubado, desativação pelo usuário, mudança de localização, e gráfico de erros/alertas por intervalo. |
| **Diagnóstico** | ~40 padrões conhecidos classificados em Crítico, Atenção, Informativo e Ruído conhecido. Cada item traz o que significa, **como resolver** passo a passo (comandos para o sistema do log, com botão *Copiar*, já preenchidos com o tenant e as interfaces), documentação oficial, pesquisa na documentação/comunidade/base de conhecimento e exemplos do log. |
| **Não classificados** | Erros e alertas sem padrão conhecido, agrupados e normalizados, com atalho de pesquisa. |
| **Arquivos** | Arquivos lidos, linhas, erros, alertas e período de cada um. |
| **Explorador** | Busca em todas as linhas, com filtro por nível e por arquivo. |

Também detecta VPNs de terceiros em execução (FortiClient, Zscaler, GlobalProtect, AnyConnect…), interfaces de VPN órfãs com DNS internos, dependências ausentes e versão divergente. O relatório pode ser **copiado** ou **salvo** em Markdown para anexar ao chamado.

Formatos lidos: `nsdebuglog.log`, `npadebuglog.log`, `nsApp.log`, `nsAppUI.log`, `nsInstallation.log`, `nsDiag-*.log`, `install.log`, `network-state.log`, `appInfo.log` e os JSON de configuração (`nsconfig.json`, `eventcache.json`, `nsuser.conf`, `nssteering.json`). Aceita `.zip` (inclusive aninhados), pastas e arquivos soltos, de clientes Windows, macOS e Linux.

## Instalação (Windows 10/11 x64)

Baixe na página de [Releases](../../releases):

- **`NetskopeLogAnalyzer-<versão>-Setup.exe`** — instala em `C:\Program Files\Netskope Log Analyzer`, cria atalho no Menu Iniciar, aparece em *Aplicativos instalados* e adiciona o app em *Abrir com* para `.zip` e `.log`.
- **`NetskopeLogAnalyzer-<versão>-portatil.zip`** — só o `.exe`, para usar sem instalar.

Uso: abra o app e arraste o `.zip` de logs para a janela (ou *Abrir pacote…*). Também dá para clicar com o botão direito no `.zip` > *Abrir com* > *Netskope Log Analyzer*.

> **Liberação pelo TI:** os executáveis não têm assinatura digital, então o Windows (SmartScreen / Controle Inteligente de Aplicativos / AppLocker) pode bloqueá-los até serem liberados. Veja [docs/LIBERACAO-TI.md](docs/LIBERACAO-TI.md) — inclui instalação silenciosa e os hashes SHA-256 de cada versão.

## Desenvolvimento

```
NetskopeLogAnalyzer.sln
src/NetskopeLogAnalyzer.Core/    motor de análise (net8.0): leitura de zip, parser, regras, resoluções, relatório
src/NetskopeLogAnalyzer/         app WPF (net8.0-windows)
tests/NetskopeLogAnalyzer.Tests/ xUnit com pacote de logs sintético
installer/                       script do instalador (Inno Setup 6)
assets/                          ícones
docs/LIBERACAO-TI.md             guia de liberação e implantação para o TI
build.ps1                        testa e gera Setup.exe, portátil e SHA256SUMS.txt em dist\
.github/workflows/release.yml    compila e testa a cada push; publica a release quando VERSION muda
```

Requisitos: [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) e, para o `Setup.exe`, [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
dotnet run --project src\NetskopeLogAnalyzer          # rodar em modo dev
dotnet test                                          # testes
powershell -ExecutionPolicy Bypass -File .\build.ps1 # gerar pacotes em dist\
```

**Nova versão:** altere `VERSION` (ex.: `2.0.1`) e `RELEASE_NOTES.md`, faça commit e push na `main`. O GitHub Actions testa, compila num runner Windows e publica a release com os pacotes e os hashes.

### Adicionar um novo padrão de erro
Em `src/NetskopeLogAnalyzer.Core/KnowledgeBase.cs`:
1. Adicione uma regra em `Rules` com `R(id, regex, severidade, categoria, título, significado, ação, ...)`. Use `any: true` para casar em qualquer nível de log e `byCount:` para severidade por quantidade.
2. Adicione a resolução em `Fixes[id]`: passos `S(texto, comando)` em `All`, `Linux`, `Windows`, `Mac` e `End`, mais `Refs` (chaves de `Refs`) e `Query` (termos de pesquisa).
3. Nos comandos, `{NSD}` vira o caminho do `nsdiag` do sistema do log e `{T}` vira o tenant extraído do log.
4. Cubra com um teste em `tests/`.

## Aviso

**Nunca faça commit de pacotes de logs reais neste repositório.** O `.gitignore` já bloqueia `NetskopeLogs*.zip`, `*.log` e `authtoken.pem`; os testes usam logs sintéticos.

As resoluções foram montadas a partir da documentação pública da Netskope (nov/2026) e não substituem o suporte oficial.
