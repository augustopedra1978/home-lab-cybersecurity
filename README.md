# 🛡️ Home Lab de Cibersegurança — Wazuh SIEM/XDR, Hardening CIS e Integração Multi-SIEM

> **Laboratório doméstico de cibersegurança para desenvolvimento de competências práticas em Blue Team / SOC / GRC**
> **Período:** Junho a Julho de 2026
> **Autor:** Analista em transição de carreira para Cibersegurança (Blue Team / SOC / GRC / OT-ICS Security)

![Wazuh](https://img.shields.io/badge/Wazuh-4.14.5-blue)
![Ubuntu](https://img.shields.io/badge/Ubuntu_Server-24.04.4_LTS-orange)
![Windows](https://img.shields.io/badge/Windows_11-Pro-blue)
![CIS](https://img.shields.io/badge/CIS_Benchmark-47%25→87%25-success)
![Suricata](https://img.shields.io/badge/Suricata-8.0.6-red)
![Sysmon](https://img.shields.io/badge/Sysmon-15.21-lightgrey)
![Splunk](https://img.shields.io/badge/Splunk-Integrated-black)
![BitLocker](https://img.shields.io/badge/BitLocker-TPM%2BPIN-green)

---

## 📋 Sumário

1. [Visão Geral do Projeto](#1-visão-geral-do-projeto)
2. [Arquitetura do Home Lab](#2-arquitetura-do-home-lab)
3. [Fase 1 — Fundação: Instalação do Wazuh](#3-fase-1--fundação-instalação-do-wazuh)
4. [Fase 2 — Hardening CIS Benchmark (47% → 87%)](#4-fase-2--hardening-cis-benchmark-47--87)
5. [Fase 3 — Criptografia de Disco (BitLocker)](#5-fase-3--criptografia-de-disco-bitlocker)
6. [Fase 4 — Integrações Multi-SIEM (Splunk, Sysmon, Suricata)](#6-fase-4--integrações-multi-siem-splunk-sysmon-suricata)
7. [Fase 5 — Acesso Remoto Seguro](#7-fase-5--acesso-remoto-seguro)
8. [Fase 6 — Auditoria Pós-Hardening](#8-fase-6--auditoria-pós-hardening)
9. [Hardening de Rede Doméstica](#9-hardening-de-rede-doméstica)
10. [Gestão de Vulnerabilidades — Caso CVE-2026-43503](#10-gestão-de-vulnerabilidades--caso-cve-2026-43503)
11. [Lições Aprendidas e Causas-Raiz Notáveis](#11-lições-aprendidas-e-causas-raiz-notáveis)
12. [Competências Técnicas Demonstradas](#12-competências-técnicas-demonstradas)
13. [Limitações Conhecidas e Roadmap](#13-limitações-conhecidas-e-roadmap)

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
| Wazuh Indexer | 4.14.5 | Motor de busca (OpenSearch) |
| Wazuh Manager | 4.14.5 | Motor de análise e correlação (OSSEC) |
| Wazuh Dashboard | 4.14.5 | Interface web de visualização |
| Filebeat OSS | 7.10.2 | Pipeline Manager → Indexer |
| Wazuh Agent | 4.14.5 | Coleta de dados no endpoint Windows |
| Sysmon | 15.21 | Telemetria profunda de processos/registro (config SwiftOnSecurity) |
| Suricata | 8.0.6 | IDS de rede (Emerging Threats Open ruleset) |
| Splunk Enterprise / Universal Forwarder | 10.x / 10.4.1 | SIEM secundário e pipeline de encaminhamento |
| Tailscale | 1.98.8 | VPN mesh (WireGuard) para acesso remoto |
| BitLocker | Nativo Windows 11 Pro | Criptografia de disco (TPM+PIN) |

---

## 2. Arquitetura do Home Lab

```
┌───────────────────────────────────────────────────────────────────┐
│                        REDE DOMÉSTICA (exemplo)                    │
│                         192.168.0.0/24                              │
│                                                                     │
│  ┌────────────────────────────────────┐   ┌──────────────────────┐│
│  │      NOTEBOOK WINDOWS 11 PRO        │   │   VM UBUNTU SERVER   ││
│  │      (IP fixo reservado por MAC)    │   │   (IP fixo por MAC)  ││
│  │                                     │   │                      ││
│  │  ┌───────────────┐                  │   │  ┌────────────────┐ ││
│  │  │  Wazuh Agent   │──── TCP 1514 ───┼───┼─▶│ Wazuh Manager  │ ││
│  │  │  Sysmon 15.21  │                  │   │  ├────────────────┤ ││
│  │  │  Suricata 8.0.6│                  │   │  │ Wazuh Indexer  │ ││
│  │  ├───────────────┤                  │   │  │  (OpenSearch)  │ ││
│  │  │ Splunk         │◀── NAT 10.0.3.x─┼───┼──┤ Filebeat       │ ││
│  │  │ Enterprise     │   (Universal    │   │  ├────────────────┤ ││
│  │  │ (porta 9997)   │    Forwarder)   │   │  │Wazuh Dashboard │ ││
│  │  ├───────────────┤                  │   │  │ (porta 443)    │ ││
│  │  │ BitLocker      │                  │   └──┴────────────────┘ ││
│  │  │ (TPM + PIN)    │      NIC1: Bridge (LAN) ─┘                  ││
│  │  ├───────────────┤      NIC2: NAT (10.0.3.x, host-only interno)││
│  │  │ Tailscale      │                                             ││
│  │  │ (VPN mesh)     │                                             ││
│  │  └───────────────┘                                             ││
│  └────────────────────────────────────┘                            │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────┐     │
│  │  ROTEADOR — DHCP + NextDNS (DoH/DoT) + WPA2/WPA3          │     │
│  └──────────────────────────────────────────────────────────┘     │
│                                                                     │
│  Outros dispositivos: Smart TV, smartphones, smartwatch,           │
│  notebook secundário, desktop — todos com NextDNS configurado      │
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

### 3.5 Resultado Final da Fase 1

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

## 11. Lições Aprendidas e Causas-Raiz Notáveis

### 11.1 Backup Preventivo Antes de Qualquer Mudança Estrutural

Snapshots de VM e backups de arquivos de configuração (`ossec.conf`, `suricata.yaml`) antes de qualquer alteração permitiram reversão rápida em múltiplos incidentes, sem retrabalho.

### 11.2 Falso Negativo por Incompatibilidade de Idioma no Scanner SCA

Os 27 controles de auditoria (Seção 17 do CIS Benchmark) foram configurados corretamente via `auditpol` e validados manualmente — mas o Wazuh SCA busca por strings de resultado em **inglês** (`"Success and Failure"`), enquanto o sistema operacional, em português, retorna `"Êxito e Falha"`. O scanner nunca reconhece o controle como aprovado, independentemente da configuração real do sistema — uma limitação documentada da ferramenta, não uma falha de hardening.

### 11.3 Validação Empírica Sempre Antes de Aceitar uma Hipótese

Repetidas vezes ao longo do projeto, hipóteses plausíveis (causa de travamento de VM, causa de bloqueio do BitLocker, causa de falha do Splunk) precisaram ser descartadas ou refinadas mediante evidência direta de log — nunca aceitas por plausibilidade isolada. O processo de eliminação sistemática (testar e descartar, uma hipótese de cada vez) foi mais eficaz do que qualquer suposição individual, por mais razoável que parecesse inicialmente.

### 11.4 Mudança de Edição de Sistema Operacional Não Substitui Hardening Ativo

A migração de Windows 11 Home para Pro **não alterou** automaticamente nenhuma configuração de segurança — apenas disponibilizou ferramentas (Editor de Política de Grupo Local, Hyper-V) que exigiram configuração manual subsequente para impactar a pontuação de conformidade. Confirmado empiricamente por duas varreduras SCA idênticas, pós-migração, antes de qualquer hardening adicional.

### 11.5 Controles de Segurança Podem Entrar em Conflito Entre Si

O caso do BitLocker bloqueado pela exigência de backup em Active Directory (Seção 5.2) ilustra um padrão importante: um controle de conformidade correto **em seu contexto de origem** (ambientes corporativos com domínio) pode criar um impasse funcional real em outro contexto (ambiente doméstico standalone). Identificar e documentar essas exceções — em vez de aplicar controles cegamente — é uma competência central de GRC.

### 11.6 Proteção de Sessões Longas via `tmux`

Instalações e processos demorados executados via SSH ficam vulneráveis à queda da própria sessão (instabilidade de rede, suspensão do host, fechamento acidental do terminal). O uso de `tmux new -s sessao` antes de iniciar qualquer processo longo garante que ele continue em execução no servidor remoto mesmo que a conexão SSH seja interrompida — bastando reconectar com `tmux attach -t sessao` para retomar o acompanhamento.

---

## 12. Competências Técnicas Demonstradas

| Área | Evidência |
|---|---|
| **SIEM/XDR** | Instalação, configuração e operação completa do Wazuh 4.14.5 |
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
| **Documentação técnica** | Relatórios estruturados, rastreáveis e reprodutíveis |

**Frameworks referenciados:** CIS Controls v8 · CIS Benchmark (Microsoft Windows 11) · MITRE ATT&CK · NIST SP 800-53 (mapeamento via Wazuh SCA)

---

## 13. Limitações Conhecidas e Roadmap

### 13.1 Limitações Conhecidas (Documentadas, Não Resolvidas)

| Item | Status |
|---|---|
| Instabilidade ocasional de boot da VM (kernel panic intermitente) | Causa raiz não determinada com certeza; mitigada (não eliminada) por ajuste do provedor de paravirtualização; contorna-se com nova tentativa de boot, sem perda de dados |
| Credential Guard configurado mas não ativo em runtime | Bloqueado por ausência de opção de VT-d/IOMMU exposta na BIOS do hardware — HVCI permanece ativo e funcional como camada de proteção equivalente disponível |
| 2 controles bloqueados por ACL do sistema (News/Widgets) | Bloqueio de escrita mesmo com permissão de Administrador — hipótese não confirmada de interferência do Tamper Protection/ASR |

### 13.2 Roadmap

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
