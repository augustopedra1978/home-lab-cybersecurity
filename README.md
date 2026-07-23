# 🛡️ Home Lab de Cibersegurança — Wazuh SIEM/XDR, Hardening CIS e Integração Multi-SIEM

> **Laboratório doméstico de cibersegurança para desenvolvimento de competências práticas em Blue Team / SOC / GRC**
> **Período:** Junho a Julho de 2026
> **Autor:** Profissional de Cibersegurança (Blue Team / SOC / GRC / OT-ICS Security)

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.6-blue)
![Ubuntu](https://img.shields.io/badge/Ubuntu_Server-24.04.4_LTS-orange)
![Windows](https://img.shields.io/badge/Windows_11-Pro-blue)
![CIS](https://img.shields.io/badge/CIS_Benchmark-24%25→87%25-success)
![Suricata](https://img.shields.io/badge/Suricata-8.0.6-red)
![Sysmon](https://img.shields.io/badge/Sysmon-15.21-lightgrey)
![Splunk](https://img.shields.io/badge/Splunk-Integrated-black)
![BitLocker](https://img.shields.io/badge/BitLocker-TPM%2BPIN-green)

---

## 📋 Sumário

1. [Visão Geral do Projeto](#1-visão-geral-do-projeto)
2. [Arquitetura do Home Lab](#2-arquitetura-do-home-lab)
3. [Fase 1 — Fundação: Instalação do Wazuh](#3-fase-1--fundação-instalação-do-wazuh)
4. [Fase 2 — Hardening CIS Benchmark (24% → 87%)](#4-fase-2--hardening-cis-benchmark-24--87)
5. [Fase 3 — Criptografia de Disco (BitLocker)](#5-fase-3--criptografia-de-disco-bitlocker)
6. [Fase 4 — Integrações Multi-SIEM (Splunk, Sysmon, Suricata)](#6-fase-4--integrações-multi-siem-splunk-sysmon-suricata)
7. [Fase 5 — Acesso Remoto Seguro](#7-fase-5--acesso-remoto-seguro)
8. [Fase 6 — Auditoria Pós-Hardening](#8-fase-6--auditoria-pós-hardening)
9. [Hardening de Rede Doméstica](#9-hardening-de-rede-doméstica)
10. [Gestão de Vulnerabilidades — Caso CVE-2026-43503](#10-gestão-de-vulnerabilidades--caso-cve-2026-43503)
11. [Fase 7 — Manutenção Contínua e Resposta a Incidentes](#11-fase-7--manutenção-contínua-e-resposta-a-incidentes)
12. [Fase 8 — Dashboards Personalizados e Diagnóstico de Integração](#12-fase-8--dashboards-personalizados-e-diagnóstico-de-integração-22072026)
13. [Lições Aprendidas e Causas-Raiz Notáveis](#13-lições-aprendidas-e-causas-raiz-notáveis)
14. [Competências Técnicas Demonstradas](#14-competências-técnicas-demonstradas)
15. [Limitações Conhecidas e Roadmap](#15-limitações-conhecidas-e-roadmap)

---

## 1. Visão Geral do Projeto

Este projeto documenta a construção, operação e hardening contínuo de um laboratório doméstico de cibersegurança, com foco em:

- Implantação e operação de um SIEM/XDR (Wazuh) em ambiente virtualizado
- Hardening de endpoint Windows 11 segundo o **CIS Benchmark v3.0.0**, elevando a pontuação de conformidade de **47% para 87%**
- Criptografia de disco completo com TPM+PIN (BitLocker)
- Integração de três fontes de dados de segurança (Sysmon, Suricata, Wazuh nativo) com um SIEM secundário (Splunk)
- Configuração de acesso remoto seguro sem exposição de portas à internet
- Auditoria contínua de efeitos colaterais do hardening sobre a usabilidade real do sistema
- Documentação rigorosa de causas-raiz para cada incidente técnico, com validação empírica antes de qualquer correção

> **Nota de sanitização:** endereços IP, endereços MAC, nomes de familiares e identificadores de rede específicos foram substituídos por valores genéricos/didáticos ao longo deste documento. A estrutura técnica e os resultados reais foram preservados integralmente.

### Stack Tecnológica

| Componente | Versão | Função |
|---|---|---|
| Oracle VirtualBox | 7.2.8 | Hipervisor no host Windows |
| Ubuntu Server | 24.04.4 LTS | Sistema operacional do servidor Wazuh |
| Wazuh Indexer | 4.14.6 | Motor de busca (OpenSearch) |
| Wazuh Manager | 4.14.6 | Motor de análise e correlação (OSSEC) |
| Wazuh Dashboard | 4.14.6 | Interface web de visualização |
| Filebeat OSS | 7.10.2 | Pipeline Manager → Indexer |
| Wazuh Agent | 4.14.6 | Coleta de dados no endpoint Windows |
| Sysmon | 15.21 | Telemetria profunda de processos/registro (config SwiftOnSecurity) |
| Suricata | 8.0.6 | IDS de rede (Emerging Threats Open ruleset) |
| Splunk Enterprise / Universal Forwarder | 10.x / 10.4.1 | SIEM secundário e pipeline de encaminhamento |
| Tailscale | 1.98.8 | VPN mesh (WireGuard) para acesso remoto |
| BitLocker | Nativo Windows 11 Pro | Criptografia de disco (TPM+PIN) |

---

## 2. Arquitetura do Home Lab

```
┌───────────────────────────────────────────────────────────────────┐
│                        REDE DOMÉSTICA (exemplo)                   │
│                         192.168.0.0/24                            │
│                                                                   │
│  ┌────────────────────────────────────┐   ┌──────────────────────┐│
│  │      NOTEBOOK WINDOWS 11 PRO       │   │   VM UBUNTU SERVER   ││
│  │      (IP fixo reservado por MAC)   │   │   (IP fixo por MAC)  ││
│  │                                    │   │                      ││
│  │  ┌───────────────┐                 │   │  ┌────────────────┐  ││
│  │  │  Wazuh Agent   │────TCP 1514 ───┼───┼─▶│ Wazuh Manager  │ ││
│  │  │  Sysmon 15.21  │                │   │  ├────────────────┤  ││
│  │  │  Suricata 8.0.6│                │   │  │ Wazuh Indexer  │  ││
│  │  ├───────────────┤                 │   │  │  (OpenSearch)  │  ││
│  │  │ Splunk         │◀──NAT 10.0.3.x┼───┼──┤ Filebeat       │   ││
│  │  │ Enterprise     │   (Universal   │   │  ├────────────────┤  ││
│  │  │ (porta 9997)   │    Forwarder)  │   │  │Wazuh Dashboard │  ││
│  │  ├───────────────┤                 │   │  │ (porta 443)    │  ││
│  │  │ BitLocker      │                │   └──┴────────────────┘  ││
│  │  │ (TPM + PIN)    │      NIC1: Bridge (LAN) ─┘                ││
│  │  ├───────────────┤      NIC2: NAT (10.0.3.x, host-only interno)││
│  │  │ Tailscale      │                                           ││
│  │  │ (VPN mesh)     │                                           ││
│  │  └───────────────┘                                            ││
│  └────────────────────────────────────┘                           │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  ROTEADOR — DHCP + NextDNS (DoH/DoT) + WPA2/WPA3         │     │
│  └──────────────────────────────────────────────────────────┘     │
│                                                                   │
│  Outros dispositivos: Smart TV, smartphones, smartwatch,          │
│  notebook secundário, desktop — todos com NextDNS configurado     │
└───────────────────────────────────────────────────────────────────┘
```

### Decisões de Arquitetura

| Decisão | Justificativa |
|---|---|
| VM em modo **Bridge** (não NAT/Host-Only) | Permite comunicação direta agente↔manager na LAN, sem camada de NAT adicional |
| **Segunda placa de rede em modo NAT** na VM | Contorna uma limitação real do VirtualBox (tráfego VM→host via Bridge sobre Wi-Fi é instável) — usada exclusivamente para comunicação VM→Splunk e redirecionamento de porta do Dashboard |
| **IP fixo por MAC binding** no roteador (VM e notebook) | Evita quebra de conectividade por renovação de lease DHCP e garante rastreabilidade consistente em logs de segurança ao longo do tempo |
| **NextDNS via DHCP** no roteador | Filtragem de DNS para toda a rede, sem configuração individual por dispositivo |
| **Splunk como SIEM secundário**, alimentado via `alerts.json` do Wazuh | Evita duplicação de ingestão (dados brutos do Sysmon/Suricata não vão direto ao Splunk — passam primeiro pela análise e enriquecimento do Wazuh) |

---

## 3. Fase 1 — Fundação: Instalação do Wazuh

### 3.1 Primeira Tentativa — Falha Imediata

```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
# Erro: bash: ./wazuh-install.sh: No such file or directory
```

**Causa:** URL de versão incorreta fez o `curl` exibir o conteúdo do script na tela em vez de salvá-lo como arquivo.

### 3.2 Problema Crítico — Timeout Silencioso via IPv6

**Sintoma:** O script oficial travava indefinidamente na etapa `Starting Wazuh indexer installation`, sem nenhuma mensagem de erro, por horas.

**Diagnóstico:**
```bash
ps aux | grep apt
# root  2673  apt-get install wazuh-indexer=4.14.5-* -y -q   (travado há horas)

wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_4.14.5-1_amd64.deb
# Connecting to packages.wazuh.com|2600:9000:...|:443... failed: Connection timed out

wget -4 https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_4.14.5-1_amd64.deb
# Connecting to packages.wazuh.com|13.227.207.4|:443... connected. 200 OK
```

**Causa raiz confirmada:** O servidor `packages.wazuh.com` (hospedado em CloudFront) retorna endereços IPv6 como primeira opção de conexão. A rede de fibra GPON utilizada não roteava IPv6 corretamente para esse servidor específico, causando timeout silencioso — mascarado pela flag `-q` (silenciosa) do `apt-get` usada internamente pelo script oficial.

**Solução aplicada:** Download dos pacotes `.deb` via navegador do Windows (IPv4 nativo, ~350 Mbps confirmados) e transferência para a VM via pasta compartilhada do VirtualBox / SCP — reduzindo o tempo de transferência de horas (timeout) para segundos.

### 3.3 Problema — Certificados TLS Ausentes

**Sintoma:** `wazuh-indexer.service` falhava ao iniciar (`exit code 1`, `OpenSearchException`) após instalação manual via `dpkg`.

**Causa:** A instalação manual (pacote por pacote) não gera automaticamente os certificados TLS que o script oficial assistido cria.

**Solução:**
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh
chmod +x wazuh-certs-tool.sh
sudo bash wazuh-certs-tool.sh -A
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

### 3.4 Outros Problemas Resolvidos Nesta Fase

| Problema | Causa | Solução |
|---|---|---|
| `unattended-upgrades` bloqueando o APT | Serviço de atualização automática do Ubuntu concorrendo pelo lock do APT | `systemctl disable/stop unattended-upgrades` |
| SSH inacessível | Serviço instalado mas inativo (`inactive (dead)`) | `systemctl enable --now ssh` |
| Caracteres especiais incorretos no teclado da VM | Layout `us` sem persistência ABNT2 | Uso exclusivo de SSH a partir do Windows, eliminando dependência do console gráfico |
| `chmod` com wildcard falhando (`cannot access '*'`) | Ordem incorreta — diretório restringido (500) antes dos arquivos | Aplicar `chmod 400` nos arquivos **antes** de `chmod 500` no diretório |

### 3.5 Operação Contínua — Incidentes Adicionais

Após a instalação, a operação diária do laboratório revelou mais 5 incidentes técnicos, cada um investigado e corrigido com validação empírica.

**a) Corrupção do pipeline Filebeat → Indexer**

*Sintoma:* Índices `wazuh-alerts-*` ausentes no Dashboard, nenhum evento sendo exibido.

*Causa raiz:* Um comando `curl` executado sem tratamento de resposta sobrescreveu `/etc/filebeat/filebeat.yml` com uma página de erro XML (`AccessDenied`) retornada por um bucket S3, corrompendo o arquivo de configuração.

*Correção:* Reconstrução dos certificados TLS do Filebeat, novo download do template `wazuh-template.json` e do módulo `wazuh-filebeat-0.5.tar.gz` (ausente), validação via `filebeat test output`.

**b) Daemon `wazuh-remoted` inoperante**

*Sintoma:* API do Manager retornando erro `wazuh-remoted->failed`, timeout no carregamento do Dashboard.

*Causa raiz:* PID órfão referenciado em arquivo de lock, resultante de um restart anterior do `wazuh-manager` interrompido de forma anômala.

*Correção:* Identificação e remoção do processo órfão, restart limpo via `systemctl`.

**c) Travamento intermitente da VM por suspensão do host**

*Sintoma:* Console da VM travado, SSH e HTTPS retornando `ERR_CONNECTION_TIMED_OUT`.

*Causa raiz:* O host físico entrava em suspensão de energia durante sessões prolongadas, mesmo com a configuração nativa do Windows ajustada para "nunca suspender" — confirmado via eventos `Kernel-Power ID 42` no Visualizador de Eventos.

*Correção (três camadas redundantes):*
```powershell
powercfg /requestsoverride PROCESS "VirtualBoxVM.exe" SYSTEM
```
Somada ao ajuste da política "Fechar a tampa" (distinta da suspensão geral) e à identificação de um utilitário OEM de gerenciamento de energia do fabricante do notebook, que mantinha uma política de suspensão paralela não visível no Painel de Controle nativo.

**d) Bloqueio de tela recorrente em intervalo curto**

*Sintoma:* Bloqueio de sessão a cada ~1 minuto, mesmo após configuração da política de inatividade CIS para 900 segundos (15 min).

*Causa raiz:* Conflito entre dois mecanismos independentes do Windows — a política de bloqueio por inatividade (`InactivityTimeoutSecs`, via CIS) e o protetor de tela legado (`ScreenSaveTimeOut`), configurado separadamente com valor muito menor.

*Correção:* Desativação visual do protetor de tela, preservando integralmente a política de segurança de bloqueio por inatividade. Bloqueio passou de ~1 minuto para ~18 minutos médios em teste empírico — sem regressão de segurança.

**e) Ruído de alto volume no módulo FIM (File Integrity Monitoring)**

*Sintoma:* Mais de 25.000 eventos/dia classificados sob a técnica MITRE ATT&CK T1565.001 (Manipulação de Dados Armazenados), degradando a relação sinal-ruído do SIEM.

*Causa raiz:* O escopo de monitoramento FIM sobre `Program Files` capturava a escrita contínua dos bancos de dados internos de uma ferramenta de terceiros usada para estudo comparativo.

*Correção:*
```xml
<ignore type="sregex">c:\\arquivos de programas\\splunk\\.*</ignore>
```
Volume caiu de dezenas de milhares para zero eventos de ruído nas horas seguintes.

### 3.6 Threat Hunting — Investigações de Anomalias

Duas investigações foram conduzidas a partir de anomalias observadas no Dashboard, seguindo processo de amostragem de eventos individuais e correlação temporal — nunca concluindo apenas pelo volume agregado:

| Investigação | Achado | Classificação |
|---|---|---|
| ~800 eventos "Autenticação bem-sucedida" em 24h | `logonType: 5` (logon de serviço), processo `services.exe`, conta `SYSTEM` — reinícios legítimos de serviços do sistema | Não é ameaça |
| Conexão SSH de IP não catalogado no roadmap | Login bem-sucedido com credencial válida, sessão de ~33 minutos, encerrada voluntariamente, originado de outro dispositivo da própria rede local | Não é ameaça |

### 3.7 Resultado Final da Fase 1

| Componente | Status |
|---|---|
| wazuh-indexer 4.14.5 | ✅ active (running) |
| wazuh-manager 4.14.5 | ✅ active (running) |
| wazuh-dashboard 4.14.5 | ✅ active (running) |
| filebeat 7.10.2 | ✅ instalado e validado |
| Agente Windows 4.14.5 | ✅ ativo, ID 001 |

**Tempo total investido nesta fase:** ~40 horas, majoritariamente consumidas pelo diagnóstico do problema de IPv6 — um problema não documentado oficialmente pela Wazuh para esse cenário de rede.

---

## 4. Fase 2 — Hardening CIS Benchmark (47% → 87%)

### 4.0 Pré-requisito: Migração Windows 11 Home → Pro

**Motivação:** Necessidade de recursos de gestão de política de grupo local (`gpedit.msc`), indisponível na edição Home, para avançar o hardening além da emulação manual via registro.

**Procedimento executado:**
1. Backup de configuração do agente Wazuh (`ossec.conf`)
2. Exportação completa da VM de laboratório em formato `.ova` (rede de segurança pré-migração)
3. Parada controlada de serviços dependentes
4. Aplicação da licença via chave de produto (upgrade *in-place*, sem reinstalação)
5. Validação pós-migração: integridade de dados/aplicativos, estado do Hyper-V (mantido desabilitado por decisão consciente, para preservar estabilidade do hipervisor em uso), funcionalidade do `gpedit.msc`, conectividade de rede da VM (0% de perda de pacotes) e reintegração dos serviços de monitoramento

**Incidente durante a migração:** Falha inicial de ativação de licença (código de erro documentado publicamente pela Microsoft como associado a problemas de chave de produto). Resolvido via contato com o canal de suporte do revendedor, com certificação de parceria de licenciamento verificável.

**Achado metodológico relevante:** a varredura CIS foi executada duas vezes após a migração de edição, com resultado idêntico em ambas (47%). Isso confirma que a mudança de edição, por si só, **não altera automaticamente** nenhuma configuração de segurança — apenas disponibiliza ferramentas (GPO local, BitLocker, Hyper-V) que exigem configuração manual subsequente para impactar a pontuação de conformidade.

Aplicação sistemática do **CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0** (482 controles totais), dividida em 6 ondas de aplicação, cada uma com triagem de risco antes da execução.

### 4.1 Progressão do Score

| Etapa | Score | Controles Aplicados |
|---|---|---|
| Baseline (Windows 11 Home, hardening manual via registro) | 24% | — |
| Baseline (pós-upgrade para Pro, antes das ondas) | 47% (227/482) | — |
| Onda 1 — Políticas de Auditoria | 47%* | 27 |
| Onda 2 — Opções de Segurança | 48% | 5 |
| Onda 3 — Serviços e Firewall | 49% | 3 |
| Onda 4 — Modelos Administrativos | 65% | 79 |
| Onda 5 — VBS / Credential Guard / BitLocker (política) / App Guard | 86% | 99 |
| Onda 6 — Sandbox / Preview Builds | **87%** | 4 |

\* *A Onda 1 foi aplicada corretamente (validado manualmente via `auditpol /get`), mas não refletiu no score visível do Dashboard — ver Seção 11.2 (causa raiz: incompatibilidade de idioma no scanner).*

### 4.2 Bugs de Script Encontrados e Corrigidos Durante a Aplicação

Cada onda envolveu geração automatizada de scripts PowerShell a partir de exportações CSV do próprio Wazuh SCA. Isso expôs bugs reais de engenharia, todos documentados e corrigidos:

| Bug | Onda | Causa | Correção |
|---|---|---|---|
| Substituição de path incorreta (`HKLM:_LOCAL_MACHINE\...`) | 4 e 5 | Uso de fatiamento de string (`path[4:]`) em vez de substituição direta (`.replace()`) | Padronização para `.replace('HKEY_LOCAL_MACHINE', 'HKLM:')` |
| Controle multi-valor aplicando só 1 de 5 valores necessários (Windows Connect Now) | 4 | Parser pegava apenas o último valor de registro por regra, não todos | Parser reescrito para capturar todos os pares nome/valor por controle |
| Colisão de "valor manual" entre dois controles com mesmo ID CIS | 4 | Dicionário de overrides indexado por ID CIS, mas dois controles distintos compartilhavam o mesmo número | Overrides indexados por (ID CIS + nome do valor), não só ID CIS |
| Formatação incorreta em "Hardened UNC Paths" | 4 | Ausência de espaço após vírgula no valor esperado pelo regex do Wazuh | Ajuste de formatação exata |
| Attack Surface Reduction aplicando 1 de 11 regras exigidas | 4 | Escopo subdimensionado do controle | Lista completa dos 11 GUIDs de regras ASR aplicada |

### 4.3 Exceções Documentadas (Risco Avaliado e Aceito)

| Categoria | Controles | Justificativa |
|---|---|---|
| Login / conta Microsoft | 3 | Risco de bloqueio confirmado por incidente histórico documentado (recuperação via ambiente de recuperação do Windows) |
| Suspensão / hibernação / timeout de tela | 2 | Mesmo padrão de risco — incidente histórico de bloqueio a cada ~1 minuto |
| Bluetooth Support Service / Print Spooler | 2 | Uso ativo confirmado (periféricos Bluetooth e impressão) |
| RDP (7 configurações de alto risco) | 7 | Usuário utiliza RDP ativamente (cliente e servidor) |
| Apps / Microsoft Store | 8 | Uso confirmado de Store e App Installer |
| BitLocker — escrita em drives removíveis não criptografados | 2 | Uso confirmado de pendrives/HDs externos sem criptografia |
| Restrição de instalação de dispositivos por ID/Classe | 6 | Exige lista de dispositivos aprovados definida pela organização — sem valor genérico seguro aplicável a ambiente doméstico; padrão de uso cobre praticamente todas as classes de dispositivo restringíveis |
| Application Guard | 6 | Dependência de hardware/feature opcional não habilitada |
| Auditoria (Seção 17, 27 controles) | 27 | Bloqueio por incompatibilidade de idioma no scanner — ver Seção 11.2 |

### 4.4 Teste de Não-Regressão Hyper-V

Antes da aplicação da Onda 5 (que habilita Virtualization Based Security), foi conduzido um teste formal de compatibilidade entre VirtualBox 7.2.8 e o Hyper-V nativo do Windows, motivado por relatos públicos de instabilidade nessa combinação de versões.

**Protocolo:**
1. Snapshot completo da VM antes de qualquer mudança
2. Habilitação do Hyper-V via `optionalfeatures`
3. Reinicialização do host
4. Validação: boot da VM, integridade dos serviços Wazuh, conectividade de rede (0% de perda de pacotes), status do agente Windows

**Resultado:** ✅ Aprovado — todos os serviços operacionais, sem regressão de rede ou funcionalidade.

---

## 5. Fase 3 — Criptografia de Disco (BitLocker)

### 5.1 Configuração

- Modo de autenticação: **TPM + PIN** (exigido via política aplicada na Onda 5 do hardening)
- Escopo de criptografia: **unidade inteira** (recomendação oficial da Microsoft para sistemas já em uso, em vez de "somente espaço usado")
- Backup da chave de recuperação: conta Microsoft + arquivo local (dupla redundância)

### 5.2 Incidente — Bloqueio por Exigência de Active Directory

**Sintoma:** `"O BitLocker não conseguiu contatar o domínio. Verifique se você está conectado à rede..."`

**Causa raiz:** O controle CIS `OSRequireActiveDirectoryBackup = 1` (aplicado na Onda 5) exige que a chave de recuperação seja armazenada no Active Directory **antes** de permitir a ativação do BitLocker no disco do sistema. Em uma máquina não ingressada em domínio, essa exigência nunca pode ser satisfeita — um impasse permanente por design.

**Solução:**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "OSRequireActiveDirectoryBackup" -Value 0
gpupdate /force
```

**Decisão documentada:** Avaliou-se ingressar o notebook em um domínio Active Directory apenas para satisfazer esse controle — descartado por desproporcionalidade (exigiria um Controlador de Domínio dedicado, rodando permanentemente, para satisfazer uma única política). Recomendado como projeto de laboratório isolado e futuro, não como solução para este bloqueio.

### 5.3 Resultado

- Criptografia da unidade completa (aprox. 932 GB) concluída em tempo consideravelmente abaixo da estimativa inicial, beneficiada pela aceleração de hardware AES-NI do processador
- Validação prática: PIN solicitado corretamente antes da tela de login em boot subsequente

---

## 6. Fase 4 — Integrações Multi-SIEM (Splunk, Sysmon, Suricata)

### 6.1 Arquitetura de Integração (Cascata, Sem Duplicação)

```
[ Sysmon ]   ──┐
               ├──▶ [ Agente Wazuh ] ──▶ [ Wazuh Manager ] ──▶ [ Splunk ]
[ Suricata ] ──┘
```

Decisão arquitetural deliberada: Sysmon e Suricata **não** enviam dados diretamente ao Splunk. Ambos são coletados pelo agente Wazuh, processados/enriquecidos pelo Manager (correlação, MITRE ATT&CK, classificação de severidade), e só então encaminhados ao Splunk através de um único canal (`alerts.json`) — evitando duplicação de ingestão e economizando recursos do host.

### 6.2 Splunk — Universal Forwarder

**Método de integração:** Splunk Universal Forwarder instalado no servidor Wazuh (VM), monitorando `/var/ossec/logs/alerts/alerts.json` e encaminhando para o Splunk Enterprise no host Windows.

> **Nota de correção metodológica:** durante a pesquisa preliminar, surgiram sugestões (de fontes externas de IA) recomendando o uso do "Wazuh App for Splunk" — esse aplicativo está em modo de manutenção mínima desde a versão 4.6 da Wazuh e **não é mais recomendado** pela documentação oficial. O método correto e ativamente mantido, usado neste projeto, é o Universal Forwarder lendo diretamente o arquivo de alertas.

**Incidentes durante a configuração:**

| Incidente | Causa | Solução |
|---|---|---|
| Licença do Splunk expirada | Trial de Enterprise de 60 dias vencido | Migração para licença **Splunk Free** (permanente, 500 MB/dia — adequada ao volume do lab) |
| `ERR_CONNECTION_REFUSED` persistente na porta de recebimento, mesmo com firewall totalmente desativado | **Limitação de rede do VirtualBox**: tráfego VM→host via placa em modo Bridge sobre Wi-Fi não completa corretamente (problema de "hairpin") | Adição de uma **segunda placa de rede em modo NAT** à VM — o VirtualBox fornece um gateway interno fixo e confiável para o host, contornando a limitação do Bridge |

**Processo de eliminação de causas** (documentado por rigor metodológico): regra de firewall específica testada → regra ampla sem restrição testada → perfil de rede (Público/Privado) corrigido → firewall totalmente desativado para teste → **ainda falhava** → confirmado que a causa era estrutural (Bridge/Wi-Fi), não configuração — resolvido definitivamente via NAT.

### 6.3 Sysmon

- Versão 15.21, configuração de linha de base da comunidade (SwiftOnSecurity)
- Agente Wazuh configurado para ler o canal `Microsoft-Windows-Sysmon/Operational`

**Incidente:** bloco `<localfile>` inserido **antes** da tag de abertura `<ossec_config>` no arquivo de configuração do agente — elemento XML fora do escopo do documento raiz, causando erro `Invalid element` e falha total do serviço do agente (`No client configured. Exiting`). Corrigido reposicionando o bloco para dentro do elemento raiz.

### 6.4 Suricata

- Versão 8.0.6, Npcap em modo compatível com WinPcap
- Instalação realizada em diretório sem espaços (`C:\Suricata`) para evitar bug conhecido de path com espaço na pasta padrão de instalação
- Ruleset: Emerging Threats Open (78 arquivos de regras, ~41.000 assinaturas carregadas)

**Incidentes e correções:**

| Incidente | Causa | Solução |
|---|---|---|
| Múltiplas referências de path hardcoded para o diretório padrão de instalação | Instalador grava `C:\Program Files\Suricata\` em 9 locais do `suricata.yaml`, independentemente do diretório de instalação escolhido | Substituição em lote de todas as ocorrências |
| Erro de parsing em 9 assinaturas (`unknown rule keyword 'file.magic'`) | Build do Suricata para Windows sem suporte a `libmagic` | Desabilitação pontual das 9 assinaturas afetadas por SID |
| `Too many fields for JSON decoder` no Wazuh Manager | Evento do tipo `stats` no `eve.json` do Suricata excede o limite de campos do decodificador JSON do Wazuh | Desabilitação do tipo de evento `stats` na configuração de saída (`eve-log`) do Suricata — mantidos `alert`, `flow`, `dns`, `http`, `tls` |

**Escopo de visibilidade (reconhecido conscientemente):** o Suricata, instalado no próprio endpoint, enxerga o tráfego de/para aquele host — não a rede doméstica inteira. Para visibilidade de rede completa seria necessário hardware adicional (Port Mirroring/SPAN em switch gerenciável, ou uma VM-gateway dedicada). Para os fins deste laboratório (proteção do endpoint e aprendizado), esse escopo foi considerado adequado e didaticamente superior (menor ruído de tráfego alheio).

---

## 7. Fase 5 — Acesso Remoto Seguro

### 7.1 Avaliação de Opções

| Opção | Avaliação |
|---|---|
| Port Forwarding direto no roteador | ❌ Descartado — exposição direta do Dashboard a varreduras automatizadas da internet |
| Cloudflare Tunnel | Viável (gratuito até 50 usuários), mas exige domínio próprio — desproporcional ao caso de uso pessoal |
| **Tailscale (VPN mesh, WireGuard)** | ✅ Escolhido — sem necessidade de portas abertas, sem custo, adequado ao uso individual |

### 7.2 Correção de Cenário de Uso

O planejamento inicial presumia acesso a partir de **outro dispositivo** (ex.: celular) enquanto o notebook permanecesse ligado em casa — cenário para o qual o Tailscale foi instalado diretamente na VM. Na prática, o caso de uso real era diferente: o **mesmo notebook físico** viajando para outras redes.

Como a VM está em modo Bridge (atrelada à rede local de casa), seu IP deixa de existir fora dessa rede. A solução aplicada foi um **redirecionamento de porta via a placa NAT** já existente (criada para o Splunk): `localhost:8443` no host → porta 443 (Dashboard) na VM, via NAT interno do VirtualBox — funcional independentemente da rede externa em que o notebook estiver.

**Validação prática:** testado com sucesso a partir de uma rede externa real (não apenas simulação em casa).

---

## 8. Fase 6 — Auditoria Pós-Hardening

Após a conclusão das 6 ondas de hardening, foi conduzida uma auditoria sistemática e proativa: reconstrução da lista exata dos 177 controles aplicados nas Ondas 4 e 5, cruzada programaticamente contra palavras-chave associadas a padrões de uso reais do usuário (dispositivos, aplicativos, serviços).

### 8.1 Bloqueios Reais Identificados e Corrigidos

| Controle | Efeito | Conflito |
|---|---|---|
| `AllowCamera = 0` | Bloqueio total de câmera (interna e futura externa) | Usuário planeja uso de webcam |
| `Turn off access to the Store = Enabled` | Bloqueio da Microsoft Store — controle distinto do já excluído anteriormente, em outra seção do benchmark | Contradição direta com exclusão já decidida para uso de Store/App Installer |
| `DisableFileSyncNGSC = 1` | Bloqueio total do cliente OneDrive | Necessário para estratégia de backup pessoal (ver Seção 9.3) |

Cada correção exigiu depuração adicional: as primeiras tentativas de reversão usaram caminhos de registro presumidos que se mostraram incorretos — só confirmados ao cruzar diretamente com os dados originais de configuração aplicada, reforçando a prática de **verificar a fonte real antes de assumir a causa**.

### 8.2 Itens Avaliados e Mantidos (Sem Conflito Real)

- Sincronização de SMS/notificações via Phone Link — recurso não utilizado
- Política de bloqueio de dispositivos incompatíveis com Kernel DMA Protection — baixo impacto no hardware em uso (notebook sem portas Thunderbolt)

---

## 9. Hardening de Rede Doméstica

### 9.1 Roteador

- WPS desabilitado
- WPA2/WPA3 configurado (modo de transição, com SAE ativo)
- NextDNS configurado via DHCP (DoH/DoT) para toda a rede
- Senha de administrador alterada
- DMZ / Port Forwarding auditados (nenhuma exposição desnecessária)
- UPnP desabilitado
- DDNS desabilitado
- Resposta a *ping* na interface WAN rejeitada
- Política padrão de firewall: *deny-all* para tráfego não solicitado
- Reserva de IP fixo por MAC binding para VM e notebook principal

### 9.2 Inventário de Dispositivos

| Dispositivo | Proteção DNS | Observação |
|---|---|---|
| VM do laboratório | NextDNS (herdado da rede) | IP fixo reservado |
| Notebook principal | NextDNS (herdado da rede) | IP fixo reservado; app NextDNS nativo também instalado (proteção fora de casa) |
| Notebook secundário | NextDNS (herdado da rede) | — |
| Desktop | NextDNS (herdado da rede) | — |
| Smart TV | NextDNS (herdado da rede) | — |
| Smartphones (2) | NextDNS (herdado da rede) | — |
| Smartwatch | NextDNS (herdado da rede) | — |

### 9.3 Estratégia de Backup (Regra 3-2-1)

Auditoria de postura de segurança identificou ausência total de backup dos dados pessoais/profissionais do notebook — item corrigido durante o mesmo ciclo do hardening:

- **Camada 1 (implementada):** OneDrive com backup automático das pastas Documentos, Área de Trabalho e Imagens (plano com 1 TB de armazenamento)
- **Camada 2 (planejada):** cópia física periódica em HD externo, com criptografia própria (BitLocker To Go)

---

## 10. Gestão de Vulnerabilidades — Caso CVE-2026-43503

Durante o período documentado, foi divulgada publicamente a vulnerabilidade **CVE-2026-43503 ("DirtyClone")** — uma escalação de privilégio local no kernel Linux (CVSS 8.8), pertencente à família *DirtyFrag*, decorrente de falha na propagação da flag `SKBFL_SHARED_FRAG` durante a clonagem de buffers de socket (`skbuff`). A correção foi incorporada ao kernel mainline (v7.1-rc5) em maio de 2026, afetando majoritariamente distribuições que habilitam namespaces de usuário sem privilégio por padrão (Debian, Ubuntu, Fedora).

**Ação realizada:**

```bash
# Executado em todas as VMs do ambiente (Wazuh Lab + VMs de estudo)
uname -r
```

**Resultado:** todas as instâncias verificadas apresentavam kernel desatualizado (vulnerável) no momento da checagem. Todas foram atualizadas e reinicializadas para aplicar a correção:

```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

**Lição prática:** a data de instalação de uma distribuição não garante proteção contra vulnerabilidades divulgadas após o build da imagem ISO utilizada — a verificação de versão de kernel e aplicação de patches deve ser um processo contínuo, não um evento único pós-instalação.

---

## 11. Fase 7 — Manutenção Contínua e Resposta a Incidentes

Sessão de manutenção pós-lançamento (~23:20 a ~01:44), cobrindo cinco frentes de trabalho: integração Splunk↔Wazuh, estabilidade de boot do Indexer, geração de relatório de compliance, atualização de pacotes/kernel, e tuning de regras de detecção.

### 11.1 Correção de Permissão — Splunk Forwarder → Wazuh

**Sintoma:** Processo do Splunk Universal Forwarder ativo, mas sem dados chegando ao índice.

**Causa raiz:** O usuário de serviço do forwarder não pertencia ao grupo `wazuh`, impedindo leitura de `/var/ossec/logs/alerts/alerts.json` (permissão 640, owner `wazuh:wazuh`).

**Correção:**
```bash
sudo usermod -aG wazuh splunkfwd
```

**Validação:** throughput real confirmado via `metrics.log` (eventos/segundo, latência de 19-53ms), com timestamp do dia da correção — eliminando ambiguidade com dados históricos.

**Item de backlog identificado:** erro de parsing JSON no Splunk (`Unexpected character while parsing backslash escape`) para alguns eventos — provavelmente relacionado a paths do agente Windows. Ajuste de `props.conf` (`INDEXED_EXTRACTIONS=json`) recomendado como próximo passo, não bloqueante.

### 11.2 Estabilidade de Boot do `wazuh-indexer`

**Sintoma:** Dashboard preso em "server is not ready yet"; `wazuh-indexer.service` em estado `failed` (timeout).

**Diagnóstico — hipóteses descartadas:**
- `vm.max_map_count`: já configurado corretamente (262144)
- Memória insuficiente: 6.3GB livres de 7.8GB
- Espaço em disco: 73% usado, não crítico

**Causa raiz:** o boot do Indexer nesta VM varia naturalmente entre ~1 e ~6 minutos (confirmado por padrão recorrente em múltiplos boots subsequentes), ocasionalmente excedendo o `TimeoutStartSec` padrão do systemd.

**Correção:**
```ini
# /etc/systemd/system/wazuh-indexer.service.d/override.conf
[Service]
TimeoutStartSec=600
```

**Validação:** cluster health confirmado `green`, 100% dos shards ativos, de forma consistente em múltiplos boots subsequentes (inclusive após um travamento inesperado da VM, tratado na seção 11.5).

---

> 🔐 **Marco de Segurança — Rotação de Credenciais**
> **21/07/2026, 02:11:18** — todo o conteúdo a partir daqui (Seções 11.3 em diante) ocorre **após** a rotação da credencial administrativa do `wazuh-indexer`, incluindo a Fase 8 completa (22/07/2026). Todo o conteúdo anterior a esta marca (Seções 1–11.2) foi documentado **antes** dessa rotação.

---

### 11.3 Rotação de Credenciais Administrativas

**Motivação:** a senha do usuário `admin` do `wazuh-indexer` foi exposta em texto puro durante uma sessão de troubleshooting — risco real que exigiu rotação imediata.

**Procedimento:**
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p 'NovaSenhaForte.'
```

**Descoberta técnica relevante:** a ferramenta de rotação exige um conjunto restrito de símbolos válidos (`. * + ? -`), rejeitando símbolos comuns como `#`, `!`, `@`. A ferramenta atualiza automaticamente a credencial no Filebeat (`filebeat.yml` + keystore), mas **não propaga automaticamente** para o Dashboard — exigindo atualização manual separada:

```bash
echo "admin" | sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore add opensearch.username --stdin --force --allow-root
echo "NovaSenhaForte." | sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore add opensearch.password --stdin --force --allow-root
sudo systemctl restart wazuh-dashboard
```

**Metodologia de diagnóstico pós-rotação:** diante de um erro de timeout no Dashboard após a troca, cada camada da stack foi testada isoladamente antes de qualquer alteração adicional — cluster health, busca em dados reais (`wazuh-alerts-*`), autenticação da API do Manager (usuário `wazuh-wui`, credencial independente da do Indexer), e o índice interno de configuração do Dashboard (`.kibana*`). Todas as camadas retornaram saudáveis; a causa restante era sessão de navegador em cache, resolvida com nova janela anônima.

### 11.4 Relatório de Compliance CIS (SCA)

Exportação `checks__8_.csv` do agente `windows-host` analisada: 482 controles totais, 406 aprovados, 63 falhados, 13 não aplicáveis — **86,6% de conformidade sobre itens aplicáveis**, consistente com o score de 87% já documentado na Fase 2.

**Achado técnico adicional:** 5 dos 13 controles "não aplicáveis" são políticas de senha local (histórico, idade, tamanho mínimo, duração de bloqueio) — plausivelmente por autenticação via conta Microsoft, que torna essas políticas locais estruturalmente inaplicáveis.

### 11.5 Travamento da VM Durante Operação Ativa

**Padrão diferente do já documentado:** enquanto o kernel panic no boot (Seção 15.1) é um evento na inicialização, este travamento ocorreu com a VM **já em execução ativa**, após múltiplos restarts de serviço em sequência (Indexer, Filebeat, Dashboard, Manager).

**Hipótese [Confiança Moderada]:** sobrecarga cumulativa de recursos — o Indexer sozinho consome ~1,4-1,9GB de memória, e reinícios sucessivos em pouco tempo podem ter esgotado algum recurso momentâneo da VM.

**Recuperação:** reboot da VM; o `wazuh-indexer` levou ~6 minutos para religar (dentro da janela de `TimeoutStartSec=600` já configurada), sem perda de dados ou necessidade de intervenção adicional.

### 11.6 Tuning de Regra de Detecção — Falsos Positivos Nível Crítico

**Sintoma:** 15 alertas classificados como "Critical" (nível 15) no Dashboard, todos sob a regra `92213` ("Executable file dropped in folder commonly used by malware", MITRE T1105).

**Investigação:** inspeção individual de cada evento (não conclusão por volume agregado) revelou dois padrões, ambos benignos e bem documentados:

| Padrão | Processo de origem | Explicação |
|---|---|---|
| `__PSScriptPolicyTest_XXXXXXXX.YYY.ps1` em `AppData\Local\Temp` | `powershell.exe` | Autoteste nativo do PowerShell (desde a v5.1) para verificar bloqueio por AppLocker/Constrained Language Mode — comportamento documentado oficialmente pela Microsoft |
| DLLs (`widevinecdm.dll`, bibliotecas de reconhecimento de fala) em pasta `msedge_chrome_Unpacker_BeginUnzipping...` | `msedgewebview2.exe` | Processo legítimo de atualização de componentes do Edge/Chromium (DRM Widevine, recursos de fala) |

**Correção — regra local de reclassificação** (`/var/ossec/etc/rules/local_rules.xml`):
```xml
<rule id="100213" level="3">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
  <field name="win.eventdata.targetFilename" type="pcre2">__PSScriptPolicyTest_</field>
  <description>PowerShell AppLocker self-test (falso positivo conhecido) - reclassificado</description>
</rule>

<rule id="100214" level="3">
  <if_sid>92213</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)msedgewebview2\.exe$</field>
  <description>Atualização legítima de componente do Edge WebView2 - reclassificado</description>
</rule>
```

A regra original `92213` permanece intacta e sensível para qualquer outro processo que tente a mesma técnica — a correção é uma exceção pontual, não um enfraquecimento geral da detecção.

---

## 12. Fase 8 — Dashboards Personalizados e Diagnóstico de Integração (22/07/2026)

### 12.1 Validação de Regressão — Comparação de Varreduras CIS

Após a sessão de manutenção da Fase 7, uma nova varredura SCA mostrou aparente queda de score (87% → 86%), levantando suspeita de regressão causada pelas mudanças do dia anterior.

**Metodologia aplicada:** em vez de aceitar a mudança de score como regressão real, os dois arquivos de exportação (`checks` de ontem e de hoje) foram comparados **controle a controle**, programaticamente, por `cis_id`.

**Resultado:** dos 482 controles, apenas 5 mudaram de status — e todos na direção positiva:

| Controle | Mudança |
|---|---|
| `1.1.1` Enforce password history | `not applicable` → `passed` |
| `1.1.2` Maximum password age | `not applicable` → `passed` |
| `1.1.3` Minimum password age | `not applicable` → `passed` |
| `1.1.4` Minimum password length | `not applicable` → `passed` |
| `1.2.1` Account lockout duration | `not applicable` → `passed` |

O número de controles **falhados permaneceu idêntico** (63 = 63) — zero regressão real. A variação percentual exibida foi efeito do denominador mudando (menos itens "não aplicável"), não de piora de postura de segurança.

**Lição reforçada:** comparar números agregados (87% vs 86%) sem examinar a composição pode gerar alarme falso — a mesma disciplina de "nunca concluir só pelo volume" aplicada a alertas de segurança vale igualmente para métricas de conformidade.

### 12.2 Construção de Dashboard Personalizado — Wazuh

Combinação de 3 fontes de dados (Wazuh nativo, Sysmon, Suricata) em um único painel visual, usando o editor nativo do Wazuh Dashboard (OpenSearch Dashboards).

**Visualizações criadas:**

| Painel | Tipo | Configuração |
|---|---|---|
| Alertas por Severidade | Pie chart | Bucket "Split slices" → Terms → campo `rule.level`, size 16 |
| Linha do Tempo - Sysmon | Vertical bar | Filtro `data.win.system.providerName:"Microsoft-Windows-Sysmon"` + bucket "X-axis" → Date Histogram |
| Top Assinaturas - Suricata | Data table | Filtro `data.alert.signature:*` + bucket "Split rows" → Terms → campo `data.alert.signature`, size 10 |

As 3 visualizações foram salvas individualmente e depois combinadas em um dashboard único (`Painel Home Lab - Visão Geral`) via **Dashboards → Create dashboard → Add** (biblioteca de visualizações salvas).

### 12.3 Construção de Dashboard Personalizado — Splunk (SPL)

O mesmo conjunto de 3 painéis foi replicado no Splunk, usando SPL (Search Processing Language) em vez do construtor visual do Wazuh — demonstrando a mesma capacidade analítica em duas ferramentas distintas.

```spl
# Painel 1 — Alertas por Severidade (Pie Chart)
index=wazuh-alerts | stats count by rule.level

# Painel 2 — Linha do Tempo Sysmon (Line Chart)
index=wazuh-alerts data.win.system.providerName="Microsoft-Windows-Sysmon" | timechart count

# Painel 3 — Top Assinaturas Suricata (Statistics Table)
index=wazuh-alerts data.alert.signature=* | stats count by data.alert.signature | sort -count | head 10
```

Cada busca foi salva via **Save As → Dashboard Panel**, agrupadas no dashboard `Painel Home Lab - Splunk` (Classic Dashboards).

### 12.4 Incidente Crítico — Perda Silenciosa de Dados por Índice Incorreto

**Sintoma:** três avisos no painel de mensagens do Splunk, incluindo: `"Received event for unconfigured/disabled/deleted index=wazuh ... Dropping them as lastChanceIndex setting in indexes.conf is not configured"`.

**Investigação:**
```bash
sudo /opt/splunkforwarder/bin/splunk btool inputs list monitor:///var/ossec/logs/alerts/alerts.json --debug
```
Revelou uma única configuração ativa (sem conflito entre arquivos), mas apontando para `index = wazuh` — índice que **não existe** (o correto, usado em toda a integração, é `wazuh-alerts`).

**Causa raiz confirmada por correlação temporal:** o timestamp do aviso (20/07, 23:50:55) corresponde, com 18 segundos de diferença, ao horário em que o arquivo `inputs.conf` foi recriado durante a sessão de manutenção da Fase 7 (`23:50 — inputs.conf criado para monitorar alerts.json`) — o arquivo foi recriado com o nome do índice incorreto (faltando o sufixo `-alerts`).

**Validação do impacto real:**
```spl
index=wazuh-alerts | stats max(_time) as ultimo_evento | eval ultimo_evento=strftime(ultimo_evento, "%Y-%m-%d %H:%M:%S")
```
Confirmou que o último evento indexado era de **20/07 23:50:37** — ou seja, o Splunk ficou **~26 horas sem receber nenhum dado novo**, descartando eventos silenciosamente, enquanto os dois dashboards construídos nas Seções 12.2 e 12.3 exibiam apenas dados históricos acumulados antes da falha, sem indicação visual de que o fluxo havia parado.

**Correção:**
```bash
sudo sed -i 's/index = wazuh$/index = wazuh-alerts/' /opt/splunkforwarder/etc/system/local/inputs.conf
sudo /opt/splunkforwarder/bin/splunk restart
```

**Validação pós-correção:** nova consulta ao "último evento" confirmou timestamp de poucos minutos após a correção, com o contador de eventos totais em elevação — fluxo restabelecido.

**Observação sobre integridade de dados:** como o Wazuh Indexer é a fonte primária dos dados (o Splunk apenas espelha via forwarder), nenhum dado de segurança foi efetivamente perdido — os eventos do período afetado permanecem íntegros e consultáveis diretamente no Wazuh, mesmo não tendo sido replicados ao Splunk.

**Lição reforçada:** um dashboard "com dados" não é, por si só, evidência de que a integração está saudável — a verificação do timestamp do evento mais recente é um passo de validação indispensável e deveria ser parte de qualquer checklist de saúde de pipeline de dados.

### 12.5 Auditoria Retroativa — Rotação de Credencial da API (`wazuh-wui`)

**Motivação:** revisão sistemática de todo o histórico do projeto identificou uma credencial padrão de instalação nunca customizada — o usuário `wazuh-wui` (conta administrativa usada pelo Dashboard para autenticar na API REST do Manager, porta 55000) mantinha a senha padrão, idêntica ao próprio nome de usuário.

**Tentativa 1 — falha silenciosa de ferramenta:**
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --api --user wazuh-wui --password '<nova-senha>'
```
Retornou `ERROR: The given user does not exist` — a ferramenta, sem os parâmetros corretos de autenticação administrativa, tentou localizar o usuário no contexto errado (usuários internos do Indexer, não usuários da API/RBAC).

**Tentativa 2 — sintaxe corrigida:**
```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh --api -u wazuh-wui -p '<nova-senha>' --admin-user wazuh-wui --admin-password 'wazuh-wui'
```
Reportou sucesso (`Updated wazuh-wui user password in wazuh dashboard`) e atualizou corretamente o arquivo de configuração do Dashboard (`/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`).

**Falha não detectada pela ferramenta:** após restart, o Dashboard passou a gerar erros recorrentes (`AxiosError: Request failed with status code 401`) em suas tarefas agendadas de monitoramento. Testes diretos de autenticação confirmaram que a **senha antiga ainda era válida na API do Manager** — ou seja, a ferramenta atualizou apenas a configuração do Dashboard, não a credencial real do lado do servidor, apesar da mensagem de sucesso.

**Correção definitiva — via API REST direta:**
```bash
TOKEN=$(curl -k -s -u wazuh-wui:wazuh-wui -X GET "https://localhost:55000/security/user/authenticate" | grep -oP '"token":\s*"\K[^"]+')
curl -k -s -X GET "https://localhost:55000/security/users?search=wazuh-wui" -H "Authorization: Bearer $TOKEN"
curl -k -X PUT "https://localhost:55000/security/users/2" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"password": "<nova-senha>"}'
```

**Validação em múltiplas camadas:** teste de autenticação direta confirmou a nova senha ativa na API; duas execuções consecutivas da tarefa agendada do Dashboard (intervalo de 5 minutos) concluídas sem erro 401.

**Lição reforçada:** a mensagem de sucesso de uma ferramenta de automação não substitui validação empírica — a mesma ferramenta que corretamente sincronizou Indexer↔Filebeat↔Dashboard na Fase 7 (Seção 11.3) falhou silenciosamente ao sincronizar Manager↔Dashboard neste caso, exigindo teste de autenticação real em cada camada antes de considerar a rotação concluída.

### 12.6 Limpeza — Remoção de Pacote de Instalação Obsoleto

Remoção do instalador `.deb` do `wazuh-indexer` versão 4.9.2 (811 MB), remanescente de uma tentativa de instalação anterior à versão final 4.14.5 em uso — arquivo de instalação isolado, sem relação com o pacote efetivamente instalado no sistema.

```bash
rm ~/wazuh-indexer_4.9.2-1_amd64.deb
```

### 12.7 Triagem — Erro de Parsing JSON no Splunk (Limitação Upstream Aceita)

**Sintoma:** erros esporádicos no log interno do Splunk (`JsonLineBreaker ... Unexpected character while parsing backslash escape: 'x'`), associados ao arquivo `alerts.json` do Wazuh — 2 ocorrências identificadas em todo o histórico do projeto.

**Investigação:** o padrão de erro foi confirmado como um **problema conhecido e documentado publicamente** no repositório oficial do Wazuh no GitHub (issue reportando a mesma mensagem exata, para o mesmo par de arquivos `archives.json`/`alerts.json` → Splunk). A causa é uma sequência `\x` presente no JSON gerado pelo próprio Wazuh, que não constitui um escape válido segundo a especificação JSON — origem no codificador do Wazuh, não em configuração local.

**Avaliação de impacto:** o evento afetado permanece íntegro e consultável diretamente no Wazuh (fonte primária dos dados); apenas a cópia espelhada no Splunk falha ao indexar esse evento específico.

**Decisão:** aceitar como limitação documentada, sem correção aplicada — justificada pela frequência muito baixa (2 eventos em semanas de operação) e pela ausência de perda real de dado de segurança (preservado na fonte primária).

### 12.8 Triagem — Assinatura Suricata "ET INFO Packed Executable Download"

**Sintoma:** 3 ocorrências da assinatura `ET INFO Packed Executable Download`, identificadas na tabela de top assinaturas construída na Seção 12.3, sem investigação individual até este ponto.

**Investigação:** inspeção do evento revelou origem, domínio e nome de arquivo:

| Campo | Valor |
|---|---|
| Domínio de origem | `au.download.windowsupdate.com` |
| Arquivo | `am_delta_<hash>.exe` |
| Porta | 80 (HTTP) |

**Classificação:** benigno — domínio oficial da Microsoft (CDN de distribuição do Windows Update); o prefixo `am_delta_` é a convenção padrão da Microsoft para pacotes incrementais de atualização de definições do Windows Defender (Antimalware).

**Observação lateral:** o IP de destino do evento pertencia a uma faixa de rede (`192.168.2.0/24`) distinta da rede doméstica documentada neste projeto (`192.168.15.0/24`), indicando que o evento ocorreu com o notebook conectado a outra rede — consistente com o uso do notebook fora de casa, sem impacto na classificação de segurança do evento em si.

**Decisão:** nenhuma ação corretiva necessária — falso positivo confirmado e encerrado.

### 12.9 Upgrade de Versão — 4.14.5 → 4.14.6

**Motivação:** o Dashboard passou a exibir aviso de atualização disponível; verificação confirmou a versão 4.14.6 (lançada em 01/07/2026) como release de manutenção cumulativa, incluindo correções de segurança (atualização de dependências criptográficas) e estabilidade (correção de segmentation fault no módulo de Vulnerability Scanner, melhorias no tratamento de descompressão de mensagens no `wazuh-remoted`).

**Contexto adicional identificado na pesquisa prévia:** relato técnico documentado publicamente de uma falha real — `wazuh-manager` travando por timeout durante um upgrade equivalente (Ubuntu 24.04, mesma série 4.14.x) — motivou uma medida preventiva antes de iniciar.

**Procedimento executado (ordem oficial: Indexer → Manager → Dashboard → Filebeat):**

1. **Backup preventivo:** snapshot completo da VM antes de qualquer alteração, mais backup individual dos arquivos de configuração de cada componente.
2. **Achado intermediário:** o repositório oficial do Wazuh (`packages.wazuh.com`) nunca havia sido configurado no sistema — decorrência direta da instalação original (Fase 1) ter sido feita via download manual de pacotes `.deb`, contornando o problema de IPv6/GPON. Corrigido antes de prosseguir (importação de chave GPG + criação de `/etc/apt/sources.list.d/wazuh.list`).
3. **Medida preventiva:** aplicado o mesmo padrão de override `TimeoutStartSec=600` já usado no Indexer (Seção 11.2), desta vez também no `wazuh-manager`, antecipando o risco de timeout documentado na pesquisa.
4. **Upgrade do Indexer:** `apt-get install --only-upgrade wazuh-indexer` — validado via versão instalada, status do serviço e `_cluster/health` (green, 100% shards).
5. **Upgrade do Manager:** `apt-get install --only-upgrade wazuh-manager` — validado via versão instalada e `wazuh-control status` (todos os daemons essenciais ativos, sem o timeout que motivou a medida preventiva).
6. **Upgrade do Dashboard:** `apt-get install --only-upgrade wazuh-dashboard` — validado via versão instalada e restart limpo do serviço.
7. **Atualização dos módulos do Filebeat:** módulo `wazuh-filebeat-0.5` e `wazuh-template.json` (compatíveis com a tag `v4.14.6`) — Filebeat permanece na mesma versão (7.10.2), compatível com o Indexer 4.14.6 segundo a documentação oficial.

**Validação final de ponta a ponta:**
- Os 3 componentes centrais confirmados em `4.14.6-1` via `apt list --installed`.
- Agente Windows confirmado `Active`.
- Novos alertas confirmados chegando em tempo real ao `alerts.json`.
- API do Manager confirmada `Online`, versão `v4.14.6`, status `Up to date` na interface do Dashboard.
- Integração com o Splunk confirmada intacta — consulta ao evento mais recente retornou timestamp de minutos após a conclusão do upgrade, sem interrupção do fluxo de dados.

**Lição reforçada:** a mesma disciplina de validação empírica (nunca aceitar mensagem de sucesso sem teste real) aplicada ao longo de toda a sessão — junto com a aplicação **preventiva** de uma correção já conhecida de outro incidente (timeout de serviço), baseada em pesquisa prévia de um risco documentado — evitou a recorrência do problema relatado por terceiros para o mesmo tipo de upgrade.

**Complemento — atualização do agente Windows:** como etapa final, o agente Windows (mantido em 4.14.5, versão igual ou inferior ao Manager, conforme exigido pela documentação oficial) também foi atualizado para 4.14.6, restabelecendo paridade total de versão em toda a stack. O instalador MSI parou o serviço `WazuhSvc` durante a substituição de arquivos, mas não o reiniciou automaticamente — corrigido manualmente e validado tanto localmente (`DisplayVersion` no registro do Windows) quanto pelo próprio Manager (`agent_control -i 001` reportando `Client version: Wazuh v4.14.6`).

---

## 13. Lições Aprendidas e Causas-Raiz Notáveis

### 13.1 Backup Preventivo Antes de Qualquer Mudança Estrutural

Snapshots de VM e backups de arquivos de configuração (`ossec.conf`, `suricata.yaml`) antes de qualquer alteração permitiram reversão rápida em múltiplos incidentes, sem retrabalho.

### 13.2 Falso Negativo por Incompatibilidade de Idioma no Scanner SCA

Os 27 controles de auditoria (Seção 17 do CIS Benchmark) foram configurados corretamente via `auditpol` e validados manualmente — mas o Wazuh SCA busca por strings de resultado em **inglês** (`"Success and Failure"`), enquanto o sistema operacional, em português, retorna `"Êxito e Falha"`. O scanner nunca reconhece o controle como aprovado, independentemente da configuração real do sistema — uma limitação documentada da ferramenta, não uma falha de hardening.

### 13.3 Validação Empírica Sempre Antes de Aceitar uma Hipótese

Repetidas vezes ao longo do projeto, hipóteses plausíveis (causa de travamento de VM, causa de bloqueio do BitLocker, causa de falha do Splunk) precisaram ser descartadas ou refinadas mediante evidência direta de log — nunca aceitas por plausibilidade isolada. O processo de eliminação sistemática (testar e descartar, uma hipótese de cada vez) foi mais eficaz do que qualquer suposição individual, por mais razoável que parecesse inicialmente.

### 13.4 Mudança de Edição de Sistema Operacional Não Substitui Hardening Ativo

A migração de Windows 11 Home para Pro **não alterou** automaticamente nenhuma configuração de segurança — apenas disponibilizou ferramentas (Editor de Política de Grupo Local, Hyper-V) que exigiram configuração manual subsequente para impactar a pontuação de conformidade. Confirmado empiricamente por duas varreduras SCA idênticas, pós-migração, antes de qualquer hardening adicional.

### 13.5 Controles de Segurança Podem Entrar em Conflito Entre Si

O caso do BitLocker bloqueado pela exigência de backup em Active Directory (Seção 5.2) ilustra um padrão importante: um controle de conformidade correto **em seu contexto de origem** (ambientes corporativos com domínio) pode criar um impasse funcional real em outro contexto (ambiente doméstico standalone). Identificar e documentar essas exceções — em vez de aplicar controles cegamente — é uma competência central de GRC.

### 13.6 Proteção de Sessões Longas via `tmux`

Instalações e processos demorados executados via SSH ficam vulneráveis à queda da própria sessão (instabilidade de rede, suspensão do host, fechamento acidental do terminal). O uso de `tmux new -s sessao` antes de iniciar qualquer processo longo garante que ele continue em execução no servidor remoto mesmo que a conexão SSH seja interrompida — bastando reconectar com `tmux attach -t sessao` para retomar o acompanhamento.

### 13.7 Postura de Patch Management Proativo

Decisão consciente de aplicar atualizações disponíveis (sistema operacional, componentes do Wazuh, dependências) assim que detectadas, em vez de adiar — motivada pelo volume constante de novas CVEs divulgadas diariamente. O upgrade completo de versão documentado na Seção 12.9 (4.14.5 → 4.14.6, com paridade restabelecida em todos os componentes, incluindo o agente) é um exemplo prático dessa postura aplicada com disciplina: backup preventivo, pesquisa de riscos conhecidos antes de agir, e validação empírica em cada etapa — patch management proativo, mas não descuidado.

---

## 14. Competências Técnicas Demonstradas

| Área | Evidência |
|---|---|
| **SIEM/XDR** | Instalação, configuração, operação e upgrade de versão completos do Wazuh (4.14.5 → 4.14.6) |
| **Administração Linux** | Ubuntu Server 24.04.4 — systemd, redes, diagnóstico de baixo nível (kernel, IPv6, permissões) |
| **Hardening Windows** | CIS Benchmark v3.0.0 — 218 controles aplicados, score elevado de 47% para 87% |
| **Análise de conformidade** | Categorização sistemática de 247 falhas por causa raiz, distinguindo bugs de exceções operacionais legítimas |
| **Gestão de exceções de risco** | Mais de 60 exceções documentadas com justificativa técnica e avaliação de risco |
| **Troubleshooting sistemático** | Mais de 15 incidentes técnicos diagnosticados por eliminação de hipóteses e evidência de log |
| **Criptografia de disco** | Implementação de BitLocker com TPM+PIN, incluindo resolução de conflito de política |
| **Integração multi-SIEM** | Arquitetura em cascata Sysmon/Suricata → Wazuh → Splunk, sem duplicação de dados |
| **IDS de rede** | Instalação, tuning de regras e resolução de incompatibilidades do Suricata |
| **Acesso remoto seguro** | VPN mesh (Tailscale) e NAT port-forwarding, sem exposição de portas à internet |
| **Gestão de vulnerabilidades** | Verificação e remediação de CVE de kernel em múltiplas VMs |
| **PowerShell / Bash** | Scripts de automação de hardening, diagnóstico e correção, com depuração de bugs reais de scripting |
| **Construção de dashboards (Wazuh e Splunk)** | Visualizações personalizadas (pizza, série temporal, tabela) combinando 3 fontes de dados, replicadas em duas ferramentas distintas (editor visual e SPL) |
| **Diagnóstico de pipeline de dados** | Identificação de perda silenciosa de dados por correlação temporal de logs, isolando causa raiz sem depender de sintomas superficiais |
| **Documentação técnica** | Relatórios estruturados, rastreáveis e reprodutíveis |

**Frameworks referenciados:** CIS Controls v8 · CIS Benchmark (Microsoft Windows 11) · MITRE ATT&CK · NIST SP 800-53 (mapeamento via Wazuh SCA)

---

## 15. Limitações Conhecidas e Roadmap

### 15.1 Limitações Conhecidas (Documentadas, Não Resolvidas)

| Item | Status |
|---|---|
| Instabilidade ocasional de boot da VM (kernel panic intermitente) | Causa raiz não determinada com certeza; mitigada (não eliminada) por ajuste do provedor de paravirtualização; contorna-se com nova tentativa de boot, sem perda de dados |
| Credential Guard configurado mas não ativo em runtime | Bloqueado por ausência de opção de VT-d/IOMMU exposta na BIOS do hardware — HVCI permanece ativo e funcional como camada de proteção equivalente disponível |
| 2 controles bloqueados por ACL do sistema (News/Widgets) | Bloqueio de escrita mesmo com permissão de Administrador — hipótese não confirmada de interferência do Tamper Protection/ASR |

### 15.2 Roadmap

- [ ] Tuning avançado de regras customizadas do Suricata
- [ ] Sessão de treinamento aprofundado em navegação de Dashboard (Wazuh) e SPL (Splunk)
- [ ] Backup físico local (Camada 2 da estratégia 3-2-1)
- [ ] Laboratório isolado de Active Directory (VM dedicada de Controlador de Domínio + VM cliente), como projeto de estudo separado
- [ ] Avaliação de VM Kali Linux para simulação controlada de ataques e geração de alertas de validação

---

<div align="center">

**Home Lab de Cibersegurança — Blue Team / SOC / GRC**
*Documentação técnica para portfólio profissional*

</div>
