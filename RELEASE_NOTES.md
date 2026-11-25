**Netskope Log Analyzer 3.2.0 — somente análise de logs em repouso**

- O app agora só analisa pacotes de logs salvos pelos usuários. Saíram o coletor de telemetria, a análise “desta máquina”, a exportação de diagnóstico, o modo `--collect` e o script `nla-collect.sh`.
- Nada é coletado nem executado na máquina do analista; a única conexão é a verificação de atualização no GitHub.
- A tela inicial mostra como pedir os logs ao usuário (Windows, macOS e Linux).
- Configurações ficaram só com as atualizações.
- Horários das capturas `.pcap` convertidos para o fuso da máquina do usuário (o mesmo dos logs), não o do analista; o relatório informa o fuso.
- Textos e recomendações reescritos para o fluxo do analista (pedir novo pacote, horário do problema), sem depender de coletor.

**Os executáveis não têm assinatura digital.** Libere pelos hashes abaixo — veja [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md).
