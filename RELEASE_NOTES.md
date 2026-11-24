**Netskope Log Analyzer 2.0.1 — app nativo para Windows**

- 2.0.1: a janela se ajusta à área útil da tela em notebooks e monitores pequenos.


- Reescrito em **C#/.NET 8 (WPF)**: não depende de navegador, Edge ou WebView2. Executável único e autocontido (não precisa do .NET instalado).
- Mesmo diagnóstico da versão anterior: ~40 padrões conhecidos, resolução passo a passo com comandos e botão *Copiar*, documentação oficial, linha do tempo, gráfico de erros, explorador de logs.
- Novo: **Salvar relatório** em Markdown, *Abrir com* para `.zip`/`.log` no Explorador, abas com contagem.
- Instalador por máquina em `C:\Program Files`, com instalação silenciosa para Intune/SCCM (`/VERYSILENT /ALLUSERS`).
- A versão web (página/PWA) foi descontinuada.

**Os executáveis não têm assinatura digital.** Para liberar no ambiente da empresa (SmartScreen, AppLocker, WDAC), use os hashes abaixo e o guia [docs/LIBERACAO-TI.md](https://github.com/rcalcic/netskope-log-analyzer/blob/main/docs/LIBERACAO-TI.md).
