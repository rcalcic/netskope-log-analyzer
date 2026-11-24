**Netskope Log Analyzer 3.0.0 — análise de experiência no nível do DEM, sem licença**

- **Incidentes com causa raiz:** cada queda ou degradação com horário de início e fim, impacto e causas prováveis ranqueadas por confiança (Wi-Fi, sinal, CPU/memória/disco, energia, perda, latência até o POP, DNS, troca de POP, ação do usuário, erro do cliente), com evidências e resolução.
- **Experience Score** 0–100 por janela de 5 min (Dispositivo, Rede, Netskope, Aplicação) e o gargalo de cada período.
- **Baseline do dispositivo:** CPU, memória, disco, E/S, bateria e Wi-Fi com mediana, p95, picos, % do tempo acima do limite, anomalias e processos pesados em cada pico.
- **Rede e Netskope:** disponibilidade do túnel, latência até cada POP medida pelo cliente, POP mais rápido, histórico de IP de saída, ping/perda/jitter, DNS, TCP até o POP e traceroute.
- **Aplicações:** tempo por fase (DNS, TCP, TLS, 1º byte) e tráfego por processo: tunelado, bypass e UDP/QUIC bloqueado.
- **Coletor de telemetria** embutido no app (Windows, `--collect` sem janela) e `nla-collect.sh` para Linux/macOS. Exporta um pacote único com logs do `nsdiag` + telemetria.
- Leitura dos *snapshots* do `nsdiag` (processos, memória, disco, Wi-Fi, interfaces) em inglês e português.
- **Atualização automática** com verificação SHA-256 e políticas do TI (`DisableUpdates`, `UpdateFeedUrl`, `DisableCollector`, `Tenant`).

**Importante:** o pacote de logs do Netskope sozinho dá as métricas que o próprio cliente registra (POPs, túneis, fluxos, erros) e fotos pontuais da máquina. O **baseline contínuo de CPU, memória, disco e Wi-Fi exige o coletor** rodando na máquina durante o período do problema.

**Os executáveis não têm assinatura digital.** Libere pelos hashes abaixo — veja [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md), que agora inclui as conexões de rede do app e as políticas.
