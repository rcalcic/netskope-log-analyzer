**Netskope Log Analyzer 4.0.0 — primeira versão estável**

**Análise direcionada pelo relato do usuário**
- Na tela inicial, marque um ou vários sintomas: Lentidão, Site ou URL não abre, Private Access, DNS, Sem navegação, Quedas e desconexões, Certificado/SSL, Aplicativo específico, Bloqueio indevido, Login/registro, Cliente desligado ou travando, Máquina lenta, Conflito com VPN, Dentro da empresa (on-prem) e Wi-Fi/rede local.
- Campos opcionais de **site afetado** e **horário do problema** (com ou sem data; sem data, vale o dia em que os logs terminam).
- O Resumo abre com o bloco **Foco da análise**: verificações por sintoma, veredito e próximos passos. O site é procurado no tráfego, no DNS e nas exceções; incidentes perto do horário são destacados.
- Diagnóstico com o filtro **◎ Relato do usuário** e os achados ligados ao relato no topo. O foco pode ser alterado sem reabrir o pacote.

**Tema escuro** com a paleta da Netskope (botão ☾/☀ e *Configurações › Aparência*).

**Desempenho e baseline de recursos**
- Novo grupo *Recursos da máquina*: tempo ligado, núcleos, CPU média desde o boot, quem mais usou CPU, processos, memória total e em uso, maiores consumidores de memória, navegadores e discos, com limites e avaliação.
- Correções: taxa por hora em logs curtos, estimativa de memória total e linhas duplicadas.

**Segurança (teste de intrusão e correções)**
- Pacotes maliciosos: limites de tamanho, de entradas e de aninhamento, detecção de *zip bomb*, extração só em memória, linhas gigantes truncadas, tempo máximo em todas as expressões regulares e limites no leitor de `.pcap`. Um arquivo ou etapa com erro não derruba a análise.
- Comandos sugeridos não aceitam mais valores do log com caracteres de shell; textos sem caracteres de controle ou bidirecionais.
- Só links `https` são abertos.
- Atualização: só hosts do GitHub, nome do instalador validado, pasta temporária aleatória, limite de tamanho, leitura estrita do `SHA256SUMS.txt` e o arquivo fica travado entre a conferência do hash e a execução.

**Correções gerais:** fuso das capturas `.pcap`, legendas duplicadas ao trocar de tema, itens informativos não aparecem mais como falha no foco.

**Os executáveis não têm assinatura digital.** Libere pelos hashes abaixo — veja [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md).
