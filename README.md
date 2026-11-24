# Netskope Log Analyzer

Aplicativo **nativo para Windows** (C#/.NET 8, WPF) que analisa o pacote de logs do **Netskope Client** — o `.zip` gerado por *Save logs* ou `nsdiag -o`. Basta abrir o arquivo: o app identifica falhas e erros conhecidos, separa o que é ruído e mostra **como resolver** cada problema, com comandos prontos e links para a documentação oficial da Netskope.

- **Sem navegador:** não usa Edge, Chrome, WebView2 nem nenhum motor web.
- **Sem dependências:** um único `.exe` autocontido; não precisa nem do .NET instalado.
- **Privado:** a análise roda inteiramente no computador. Nenhum log ou telemetria é enviado — o pacote contém token, número de série, e-mails e hostnames. As únicas conexões são a verificação de atualização no GitHub e os testes de rede do coletor (quando ligado).

## O que o app mostra

| Aba | Conteúdo |
|---|---|
| **Resumo** | Veredito, **Experience Score** (0–100), incidentes, disponibilidade do túnel, causa principal, versão do cliente, tenant, steering, POP, IP de saída e principais pontos. |
| **Incidentes** | Cada queda ou degradação com **horário de início e fim**, duração, impacto e **causas prováveis ranqueadas por confiança**, com as evidências (linhas de log e métricas) e a resolução passo a passo. |
| **Experiência** | Score por janela de 5 min dividido em Dispositivo, Rede, Netskope e Aplicação, com o gargalo de cada período. |
| **Linha do tempo** | Serviço, registro, túnel conectado/derrubado, desativação pelo usuário, troca de rede/IP de saída/POP, eventos de energia e gráfico de erros por minuto. |
| **Diagnóstico** | ~40 padrões conhecidos (Crítico, Atenção, Informativo, Ruído) com significado, **como resolver**, comandos prontos e documentação oficial. |
| **Dispositivo** | **Baseline** de CPU, memória, disco, E/S, bateria e Wi-Fi (sinal, RSSI, taxa, canal, AP): mediana, p95, mín./máx., % do tempo acima do limite, anomalias e processos mais pesados em cada pico. |
| **Rede** | Disponibilidade por túnel, latência até os POPs medida pelo próprio cliente (GSLB), POP mais rápido, histórico de IP de saída, ping/perda/jitter, DNS, TCP até o POP e traceroute. |
| **Aplicações** | Tempo por fase (DNS, TCP, TLS, 1º byte, total) dos testes do coletor e tráfego por processo/destino: tunelado, bypass e UDP/QUIC bloqueado. |
| **Não classificados / Arquivos / Explorador** | Erros sem padrão conhecido, arquivos lidos e busca em todas as linhas. |

Todos os gráficos têm faixas de limite, marcação dos incidentes e dica com o valor no ponto. O relatório pode ser **copiado** ou **salvo** em Markdown para anexar ao chamado.

## Análise equivalente ao DEM, sem licença

O Netskope DEM mede a experiência continuamente a partir do endpoint. Sem a licença, o app chega ao mesmo tipo de visibilidade combinando duas fontes:

1. **O pacote de logs do Netskope Client** (sempre). Dele o app extrai métricas que o cliente já registra: latência até cada POP a cada seleção de gateway, estados e disponibilidade dos túneis, IP de saída, fluxos tunelados/bypass/bloqueados por processo, erros por minuto e os *snapshots* que o `nsdiag` inclui (processos, memória, disco, Wi-Fi, interfaces), em inglês e português.
2. **A telemetria do coletor** (opcional, recomendada). O baseline contínuo de CPU, memória, disco, bateria e Wi-Fi **só existe se o coletor estiver rodando** na máquina: o pacote do Netskope tem apenas fotos pontuais desses dados.

Quando as duas fontes cobrem o mesmo período, a análise de causa raiz cruza tudo pelo horário: para cada incidente avalia os 5 minutos anteriores e o primeiro minuto (Wi-Fi caiu ou trocou de rede, sinal fraco, CPU/memória/disco saturados, suspensão/energia, perda até a Internet, latência até o POP, DNS, troca de POP, ação do usuário, erro do cliente) e ordena as causas por confiança. Lacunas na coleta aparecem marcadas, para não se confundirem com quedas.

**Experience Score:** média ponderada de Dispositivo (25%), Rede (30%), Netskope (25%) e Aplicação (20%), limitada pelo pior componente + 25 pontos (um gargalo grave derruba o score). Faixas: até 30 *Ruim*, até 70 *Regular*, acima de 70 *Bom*.

### Coletor de telemetria

**Windows** — no app: *Telemetria* > *Iniciar coleta* (opção de iniciar com o Windows). Também roda sem janela:

```cmd
NetskopeLogAnalyzer.exe --collect [--minutes 60] [--tenant acme] [--interval 30] [--url https://app.exemplo.com]
```

Coleta a cada 30 s CPU, memória, disco, E/S, bateria, Wi-Fi (`netsh wlan`), tráfego e top processos; a cada 60 s ping/perda/jitter (gateway e Internet), TCP 443 até `gateway-<tenant>.goskope.com` e `gateway.npa.goskope.com`, DNS e HTTP por fase; a cada 15 min traceroute até o POP; além de eventos de troca de rede, suspensão/retomada e status do `nsdiag`. Arquivos em `%LOCALAPPDATA%\NetskopeLogAnalyzer\telemetry\` (14 dias). Uso de CPU desprezível; nenhum dado sai da máquina.

**Linux/macOS** — `nla-collect.sh` (na release):

```bash
chmod +x nla-collect.sh
./nla-collect.sh -t acme -d 60          # coleta por 60 min
./nla-collect.sh --install -t acme      # contínuo (systemd --user / LaunchAgent)
./nla-collect.sh --uninstall
```

Saída em `~/nla-telemetry/`. Para analisar: abra o pacote do Netskope e os arquivos `nla-telemetry-*.jsonl` juntos (arraste todos, ou coloque no mesmo `.zip`). Em *Telemetria* > *Exportar pacote de diagnóstico* o app gera, no Windows, um único `.zip` com os logs do `nsdiag` e a telemetria. Ao abrir um pacote da própria máquina, a telemetria local é incluída automaticamente.

O formato é JSON Lines, uma amostra por linha: `{"t":"2026-11-24T10:00:00-03:00","k":"cpu","v":12.5}`. Tipos: `meta`, `cpu`, `mem`, `disk`, `diskio`, `battery`, `wifi`, `net`, `ping`, `tcp`, `dns`, `http`, `trace`, `procs`, `event`.

### Atualização automática

O app consulta a última release deste repositório na abertura (no máximo a cada 12 horas), mostra as novidades e instala com um clique. O instalador baixado só é executado se o **SHA-256 conferir** com o `SHA256SUMS.txt` da release. Pode ser desativado em *Configurações* ou pelo TI via política (veja [docs/LIBERACAO-TI.md](docs/LIBERACAO-TI.md)).

## Instalação (Windows 10/11 x64)

Baixe na página de [Releases](../../releases):

- **`NetskopeLogAnalyzer-<versão>-Setup.exe`** — instala em `C:\Program Files\Netskope Log Analyzer`, cria atalho no Menu Iniciar, aparece em *Aplicativos instalados* e adiciona o app em *Abrir com* para `.zip` e `.log`.
- **`NetskopeLogAnalyzer-<versão>-portatil.zip`** — só o `.exe`, para usar sem instalar.
- **`nla-collect.sh`** — coletor de telemetria para Linux e macOS.

Uso: abra o app e arraste o `.zip` de logs para a janela (ou *Abrir pacote…*). Também dá para clicar com o botão direito no `.zip` > *Abrir com* > *Netskope Log Analyzer*.

> **Liberação pelo TI:** os executáveis não têm assinatura digital, então o Windows (SmartScreen / Controle Inteligente de Aplicativos / AppLocker) pode bloqueá-los até serem liberados. Veja [docs/LIBERACAO-TI.md](docs/LIBERACAO-TI.md) — inclui instalação silenciosa e os hashes SHA-256 de cada versão.

## Desenvolvimento

```
NetskopeLogAnalyzer.sln
src/NetskopeLogAnalyzer.Core/    motor (net8.0): parser, regras, métricas, snapshots, baseline, score, causa raiz, relatório
src/NetskopeLogAnalyzer/         app WPF (net8.0-windows): interface, gráficos, coletor, atualização
collector/nla-collect.sh         coletor Linux/macOS
tests/NetskopeLogAnalyzer.Tests/ xUnit com pacote de logs sintético
installer/                       script do instalador (Inno Setup 6)
assets/                          ícones
docs/LIBERACAO-TI.md             guia de liberação e implantação para o TI
build.ps1                        testa e gera Setup.exe, portátil e SHA256SUMS.txt em dist\
.github/workflows/release.yml    compila e testa a cada push; publica a release quando VERSION muda
.github/workflows/smoke.yml      roda o coletor e abre todas as abas num runner Windows, com capturas de tela
```

Requisitos: [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0) e, para o `Setup.exe`, [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
dotnet run --project src\NetskopeLogAnalyzer          # rodar em modo dev
dotnet test                                          # testes
powershell -ExecutionPolicy Bypass -File .\build.ps1 # gerar pacotes em dist\
```

**Nova versão:** altere `VERSION` (ex.: `3.0.1`) e `RELEASE_NOTES.md`, faça commit e push na `main`. O GitHub Actions testa, compila num runner Windows e publica a release com os pacotes e os hashes.

### Adicionar um novo padrão de erro
Em `src/NetskopeLogAnalyzer.Core/KnowledgeBase.cs`:
1. Adicione uma regra em `Rules` com `R(id, regex, severidade, categoria, título, significado, ação, ...)`. Use `any: true` para casar em qualquer nível de log e `byCount:` para severidade por quantidade.
2. Adicione a resolução em `Fixes[id]`: passos `S(texto, comando)` em `All`, `Linux`, `Windows`, `Mac` e `End`, mais `Refs` (chaves de `Refs`) e `Query` (termos de pesquisa).
3. Nos comandos, `{NSD}` vira o caminho do `nsdiag` do sistema do log e `{T}` vira o tenant extraído do log.
4. Cubra com um teste em `tests/`.

## Aviso

**Nunca faça commit de pacotes de logs reais neste repositório.** O `.gitignore` já bloqueia `NetskopeLogs*.zip`, `*.log` e `authtoken.pem`; os testes usam logs sintéticos.

As resoluções foram montadas a partir da documentação pública da Netskope (nov/2026) e não substituem o suporte oficial.
