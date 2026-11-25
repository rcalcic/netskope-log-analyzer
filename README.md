# Netskope Log Analyzer

Aplicativo **nativo para Windows** (C#/.NET 8, WPF) que analisa o pacote de logs do **Netskope Client** — o `.zip` gerado por *Save logs* ou `nsdiag -o`. Basta abrir o arquivo: o app identifica falhas e erros conhecidos, separa o que é ruído e mostra **como resolver** cada problema, com comandos prontos e links para a documentação oficial da Netskope.

- **Sem navegador:** não usa Edge, Chrome, WebView2 nem nenhum motor web.
- **Sem dependências:** um único `.exe` autocontido; não precisa nem do .NET instalado.
- **Privado:** a análise roda inteiramente no computador do analista. Nenhum log é enviado — o pacote contém token, número de série, e-mails e hostnames. A única conexão é a verificação de atualização no GitHub.

## O que o app mostra

| Aba | Conteúdo |
|---|---|
| **Resumo** | **Usuário e máquina** (e-mail registrado, login do sistema, hostname, fabricante, modelo, série, IDs do Netskope, interfaces e IPs, forma de registro), veredito, **Experience Score** (0–100), incidentes, disponibilidade do túnel, causa principal, versão do cliente, tenant, steering, POP, IP de saída e principais pontos. |
| **Incidentes** | Cada queda ou degradação com **horário de início e fim**, duração, impacto e **causas prováveis ranqueadas por confiança**, com as evidências (linhas de log e métricas) e a resolução passo a passo. |
| **Experiência** | Score por janela de 5 min dividido em Dispositivo, Rede, Netskope e Aplicação, com o gargalo de cada período. |
| **Linha do tempo** | Serviço, registro, túnel conectado/derrubado, desativação pelo usuário, troca de rede/IP de saída/POP, eventos de energia e gráfico de erros por minuto. |
| **Diagnóstico** | ~40 padrões conhecidos (Crítico, Atenção, Informativo, Ruído) com significado, **como resolver**, comandos prontos e documentação oficial. |
| **Dispositivo** | **Baseline de recursos da máquina** a partir da foto do pacote: tempo ligado, núcleos, CPU média desde o boot, quem mais usou CPU, processos, memória total/em uso, maiores consumidores de memória, navegadores e discos, cada um com limite e avaliação. Com telemetria JSONL, séries de CPU, memória, disco e Wi-Fi. |
| **Rede** | Disponibilidade por túnel, latência até os POPs medida pelo próprio cliente (GSLB), POP mais rápido, histórico de IP de saída, ping/perda/jitter, DNS, TCP até o POP e traceroute. |
| **Aplicações** | Tráfego que o cliente registrou por processo e destino: tunelado, bypass e UDP/QUIC bloqueado. |
| **Desempenho** | Métricas no estilo do DEM tiradas só dos logs: atraso das tarefas do cliente (responsividade da máquina), travamentos internos, suspensões, processos que disputam CPU, mudanças de rede, NXDOMAIN, RTT e retransmissões até o POP do Private Access, quedas e tempo de reconexão. |
| **Configuração** | Configuração efetiva traduzida: steering, detecção on-prem (e por que a máquina está On/Off Prem), exceções, apps com certificado fixo, fail-close, permissões do usuário, licença DEM, postura. |
| **Não classificados / Arquivos / Explorador** | Erros sem padrão conhecido, arquivos lidos e busca em todas as linhas. |

No **Resumo**, o app responde às perguntas que o suporte faz primeiro (sintoma, desde quando, Internet ou Private Access, onde a máquina estava, o que mudou, o que interfere, desempenho, período coberto por cada log e próximo passo). Na aba **Rede** ficam as sessões do Private Access (POP, motivo de cada queda, tempo até reconectar), DNS e domínio de pesquisa por interface e o resumo das capturas `.pcap` do pacote (retransmissões, RST, SYN sem resposta, DNS, alertas TLS).

O app também aponta, com passo a passo: mudanças de rede em excesso e sua origem (containers Docker, VMs, VPNs), domínio de pesquisa DNS sendo anexado a nomes públicos, redes locais sobrepostas às rotas do Private Access, agentes de segurança consumindo CPU, POP mais lento que o melhor disponível e reautenticação programada (separada das quedas reais).

Todos os gráficos têm faixas de limite, marcação dos incidentes e dica com o valor no ponto. O relatório pode ser **copiado** ou **salvo** em Markdown.

## Análise direcionada pelo relato do usuário

Na tela inicial, antes de abrir o pacote, marque o que o usuário relatou (pode marcar vários): **Lentidão, Site ou URL não abre, Private Access, DNS, Sem navegação, Quedas e desconexões, Certificado/SSL, Aplicativo específico, Bloqueio indevido, Login/registro, Cliente desligado ou travando, Máquina lenta (CPU/memória), Conflito com VPN, Dentro da empresa (on-prem) e Wi-Fi/rede local**. Opcionalmente informe o **site afetado** e o **horário do problema**.

O Resumo passa a abrir com o bloco **Foco da análise**: para cada sintoma, uma lista de verificações com estado (*problema*, *atenção*, *ok*, *sem dados*), o veredito (*Problema encontrado*, *Possível causa* ou *Nada relevante nos logs*) e próximos passos. O site informado é procurado no tráfego (tunelado, bypass, DNS, erros, processos) e nas exceções do steering; o horário destaca os incidentes em ±30 min. No Diagnóstico, o filtro **◎ Relato do usuário** mostra primeiro o que tem a ver com o relato. Dá para mudar o foco depois sem reabrir o pacote.

## Tema escuro

O botão ☾/☀ no topo alterna entre claro e escuro, com a paleta da Netskope. Em *Configurações › Aparência* dá para escolher *Igual ao Windows*, *Claro* ou *Escuro*.

## Como funciona

O app analisa **pacotes de logs em repouso**: o usuário salva os logs do Netskope Client e envia ao analista, que abre o `.zip` aqui. Nada é coletado da máquina do analista nem do usuário pelo app.

**Como pedir os logs ao usuário** (salvar logo depois do problema, porque os logs giram por tamanho, e informar o horário aproximado):

- **Windows / macOS:** ícone do Netskope na bandeja (barra de menus no Mac) › *Save logs*. O `.zip` vai para a Área de Trabalho.
- **Linux:** `/opt/netskope/stagent/nsdiag -o ~/NetskopeLogs.zip`
- **Windows (linha de comando):** `"C:\Program Files (x86)\Netskope\STAgent\nsdiag.exe" -o %USERPROFILE%\Desktop\NetskopeLogs.zip`

**Métricas no estilo do DEM, sem licença:** o pacote não traz séries contínuas de CPU, memória, disco e Wi-Fi (só a foto do momento em que foi salvo), mas o próprio cliente registra sinais ao longo do tempo que o app transforma em métricas: latência até cada POP, RTT e retransmissões do túnel Private Access, estados e disponibilidade dos túneis, motivo e duração de cada queda, IP de saída, mudanças de rede, NXDOMAIN, fluxos tunelados/bypass/bloqueados, atraso das tarefas periódicas do cliente (responsividade da máquina), suspensões e a foto de processos.

A causa raiz cruza tudo pelo horário: para cada incidente avalia os 5 minutos anteriores e o primeiro minuto (troca de rede, mudanças de interface, perda/latência até o POP, falhas com o tenant, DNS, troca de POP, suspensão, ação do usuário, erro do cliente) e ordena as causas por confiança.

**Experience Score:** média ponderada de Dispositivo (25%), Rede (30%), Netskope (25%) e Aplicação (20%), limitada pelo pior componente + 25 pontos. Faixas: até 30 *Ruim*, até 70 *Regular*, acima de 70 *Bom*. Quando um componente não tem dados no pacote, o score aparece como *parcial*.

**Fuso horário:** os horários exibidos são os da máquina do usuário (o fuso registrado nos logs), inclusive os das capturas `.pcap`.

### Segurança

O pacote de logs é tratado como entrada não confiável: limites de tamanho por arquivo e total, número de entradas e profundidade de `.zip` aninhados, detecção de *zip bomb*, extração só em memória (sem gravar arquivos do pacote em disco), linhas truncadas, tempo máximo em todas as expressões regulares, limites no leitor de `.pcap` e isolamento de falhas por arquivo e por etapa. Valores vindos do log são saneados antes de entrar nos comandos sugeridos, e só links `https` são abertos.

### Atualização automática

O app consulta a última release deste repositório na abertura (no máximo a cada 12 horas), mostra as novidades e instala com um clique. O instalador baixado só é executado se o **SHA-256 conferir** com o `SHA256SUMS.txt` da release. Pode ser desativado em *Configurações* ou pelo TI via política (veja [docs/LIBERACAO-TI.md](docs/LIBERACAO-TI.md)).

## Instalação (Windows 10/11 x64)

Baixe na página de [Releases](../../releases):

- **`NetskopeLogAnalyzer-<versão>-Setup.exe`** — instala em `C:\Program Files\Netskope Log Analyzer`, cria atalho no Menu Iniciar, aparece em *Aplicativos instalados* e adiciona o app em *Abrir com* para `.zip` e `.log`.
- **`NetskopeLogAnalyzer-<versão>-portatil.zip`** — só o `.exe`, para usar sem instalar.

Uso: abra o app e arraste o `.zip` de logs para a janela (ou *Abrir pacote…*). Também dá para clicar com o botão direito no `.zip` > *Abrir com* > *Netskope Log Analyzer*.

> **Liberação pelo TI:** os executáveis não têm assinatura digital, então o Windows (SmartScreen / Controle Inteligente de Aplicativos / AppLocker) pode bloqueá-los até serem liberados. Veja [docs/LIBERACAO-TI.md](docs/LIBERACAO-TI.md) — inclui instalação silenciosa e os hashes SHA-256 de cada versão.

## Desenvolvimento

```
NetskopeLogAnalyzer.sln
src/NetskopeLogAnalyzer.Core/    motor (net8.0): parser, regras, métricas, snapshots, baseline, score, causa raiz, relatório
src/NetskopeLogAnalyzer/         app WPF (net8.0-windows): interface, gráficos, atualização
tools/NetskopeLogAnalyzer.Cli/   nla-cli: o mesmo motor na linha de comando (validação)
tests/NetskopeLogAnalyzer.Tests/ xUnit com pacote de logs sintético
installer/                       script do instalador (Inno Setup 6)
assets/                          ícones
docs/LIBERACAO-TI.md             guia de liberação e implantação para o TI
build.ps1                        testa e gera Setup.exe, portátil e SHA256SUMS.txt em dist\
.github/workflows/release.yml    compila e testa a cada push; publica a release quando VERSION muda
.github/workflows/smoke.yml      abre pacotes sintéticos e todas as abas num runner Windows, com capturas de tela
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
