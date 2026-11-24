**Netskope Log Analyzer 3.1.0 — visão de suporte/TAC e desempenho pelos logs**

- **Resumo do caso:** as perguntas que o suporte faz primeiro respondidas automaticamente (sintoma, desde quando, Internet ou Private Access, onde a máquina estava, o que mudou, o que interfere, desempenho, cobertura dos logs, próximo passo).
- **Nova aba Desempenho:** métricas no estilo do DEM sem licença e sem coletor — atraso das tarefas do cliente, travamentos internos, suspensões, processos que disputam CPU, mudanças de rede, NXDOMAIN, RTT e retransmissões do túnel Private Access, quedas e tempo de reconexão.
- **Sessões do Private Access:** cada queda com motivo (gateway sem resposta, sessão expirada, DNS, parada pelo cliente), POP, tempo sem túnel e tentativas de reconexão. Reautenticação programada deixa de contar como falha; períodos com a máquina inativa não contam como queda.
- **Novas detecções com passo a passo:** mudanças de rede em excesso e a origem (Docker/VMs/VPNs), domínio de pesquisa DNS anexado a nomes públicos, redes locais sobrepostas às rotas do Private Access, agentes de segurança com uso contínuo de CPU, POP mais lento que o melhor, atrasos de execução da máquina.
- **Nova aba Configuração:** configuração efetiva traduzida (steering, detecção on-prem e por que a máquina está On/Off Prem, exceções, cert pinning, fail-close, permissões, licença DEM).
- **Capturas .pcap/.pcapng** do pacote resumidas sem Wireshark (retransmissões, RST, SYN sem resposta, DNS, alertas TLS, principais destinos).
- Menos ruído: canal de notificação da interface (403), Firefox ausente, broker NPA, erros só da interface quando a máquina está sem rede; falhas genéricas mostram o componente (GSLB, configuração, status…). Score marcado como parcial quando falta algum componente.
- Removida a recomendação de abrir chamado: todas as resoluções são executáveis pelo próprio analista.

**Os executáveis não têm assinatura digital.** Libere pelos hashes abaixo — veja [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md).
