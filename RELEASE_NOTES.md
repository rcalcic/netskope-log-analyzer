**Netskope Log Analyzer 4.1.0 — identificação do usuário e da máquina**

- O Resumo ganhou o bloco **Usuário e máquina**, com tudo o que o pacote revela:
  - **Usuário:** e-mail registrado no Netskope, login do sistema operacional, último logon, forma de registro (convite por e-mail, IdP, UPN), registro no Private Access, sessões abertas, se o usuário está habilitado no Netskope e no Private Access, registro seguro, grupo/OU.
  - **Máquina:** hostname, fabricante, modelo, número de série, sistema, arquitetura, disco criptografado, se está marcada como gerenciada, classificação e tags do dispositivo. Em pacotes do Windows com `systeminfo`/`ipconfig`, também domínio, servidor de logon, proprietário registrado, BIOS e memória.
  - **Netskope:** tenant, tenant do Private Access, versão e data de instalação do cliente, data da CA, configuração recebida, ID do dispositivo, ID de hardware e ID do túnel.
  - **Rede:** interfaces ativas com IP e MAC (túnel Netskope e Docker identificados), IP de saída, POPs, DNS e localização (on/off-prem).
- Cada valor mostra, ao passar o mouse, o arquivo de onde veio. O botão **Copiar dados** copia o bloco inteiro.
- Quando um valor aparece mascarado em um log e completo em outro, o app usa o completo.
- O usuário (e-mail e login) também aparece no quadro lateral do Resumo e no início do relatório, que ganhou a seção “Usuário e máquina”.

**Os executáveis não têm assinatura digital.** Libere pelos hashes abaixo — veja [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md).
