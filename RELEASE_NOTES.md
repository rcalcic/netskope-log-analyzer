**Netskope Log Analyzer 4.2.1 — análise calibrada com pacotes reais**

4.2.1: corrige no tema escuro os títulos e os cabeçalhos de tabela das abas Pacote e Explorador.

Esta versão foi ajustada com 14 pacotes reais de clientes Linux (Ubuntu), coletados entre outubro e novembro, e com as investigações feitas sobre eles.

**Atual × histórico**
- O pacote traz semanas de log. Agora o que só aconteceu mais de 24 h antes da coleta (ou longe do horário informado no relato) aparece com a etiqueta **histórico** e não entra no resultado. Filtro próprio no Diagnóstico.
- A janela é configurável em *Configurações › Análise* (12 h, 24 h, 3 dias ou 7 dias).

**Histórico da máquina**
- Cada análise guarda um resumo local (máquina, usuário, versão, problemas — nunca as linhas de log).
- Ao abrir um pacote de uma máquina já analisada, o Resumo mostra **o que é novo, o que sumiu e o que continua**, além de troca de versão e de Experience Score.
- Vários pacotes da mesma máquina abertos juntos não contam mais em dobro: arquivos e linhas repetidos são lidos uma vez só.

**Diagnósticos novos (vistos nos logs reais)**
- **CA do Netskope fora do repositório de certificados do Linux**: explica por que curl, git, npm, pip, Docker, Java e aplicativos em Go falham em sites inspecionados, com os comandos para Ubuntu/Debian e Fedora/RHEL e as variáveis de ambiente.
- **Fila do filtro de tráfego cheia — pacotes descartados**, com os minutos das rajadas.
- **Consultas DNS que não chegaram ao servidor DNS da rede**, com o servidor afetado.
- **Túnel DTLS (UDP) não estabelecido** — o cliente cai para TLS (TCP), pior para chamadas.
- Erros HTTP do tenant agora mostram **qual requisição** foi recusada (ex.: “NPA-gslb pop info: HTTP 403”). As recusas do canal de notificações da interface, que se repetem a cada poucos segundos, viram ruído e não inflam mais o resultado.
- Mais mensagens internas reconhecidas como ruído; falhas de configuração e de GSLB que ficavam sem classificação agora entram nos itens certos.

**Correções**
- Tenant identificado pelo `nsconfig.json`: não confunde mais o nome do POP (ex.: `sao1`) com o tenant.
- Latência por POP sem séries soltas por IP de nó: os IPs viram o nome do POP.

**Interface mais enxuta**
- Abas consolidadas: *Experiência e desempenho* (antes duas abas) e *Pacote* (arquivos, cobertura, lacunas e mensagens não classificadas).
- **Configurações** reorganizadas: Aparência, Análise, Histórico (apagar, abrir a pasta de dados) e Atualizações (verificar agora, atualizar dali mesmo, ver novidades).
- As **novidades** de uma versão abrem dentro do app, sem navegador; depois de atualizar, o app mostra o que mudou uma vez.

**Os executáveis não têm assinatura digital.** Libere pelos hashes abaixo — veja [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md).
