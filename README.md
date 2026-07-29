# 🦉 IntelOwl Enterprise Threat Intelligence Ecosystem

Este diretório contém o projeto de arquitetura de segurança, infraestrutura como código (Docker) e integrações para implantar uma solução corporativa de **Orquestração e Análise Automatizada de Ameaças baseada no IntelOwl v6+**.

---

## 🏗️ 1. Arquitetura do Sistema e Fluxo de Análise

O IntelOwl opera como um barramento unificado de Threat Intelligence (CTI). Ele automatiza a triagem paralela de Indicadores de Comprometimento (IOCs) através de filas distribuídas de Celery no Redis, unificando os resultados estruturados em um banco de dados PostgreSQL (SSOT) de alta confiabilidade.

### Diagrama ASCII de Fluxo de Dados (Ingestão ao Alerta)

```text
               +-------------------------------------------+
               |             CANAIS DE INGESTÃO            |
               | (UI React / REST API / Webhooks / SOAR)   |
               +---------------------+---------------------+
                                     |
                                     | [POST /api/v1/job/analyze_observable]
                                     v
                        +----------------------------+
                        |   Nginx TLS Reverse Proxy  |
                        +------------+---------------+
                                     |
                                     v
                        +----------------------------+
                        |   IntelOwl Django API      | (Autenticação Token / JWT)
                        +------------+---------------+
                                     |
                                     | 1. Registra Job pendente no PostgreSQL
                                     | 2. Enfileira Tarefa Async no Redis
                                     v
                        +----------------------------+
                        |       Redis Broker         | (Fila de Tarefas / Task Queue)
                        +-----+----------------+-----+
                              |                |
         [celery_observable_queue]             [celery_file_queue]
                              |                |
                              v                v
         +------------------------+        +------------------------+
         |    Celery Worker       |        |    Celery Worker       |
         |      Observables       |        |        Files           |
         |  (IP, Dominio, Hashes) |        |   (YARA, Sandboxes)    |
         +-----------+------------+        +-----------+------------+
                     |                                 |
                     +----------------+----------------+
                                      |
         +----------------------------v-----------------------------+
         |               MÓDULOS DE ANÁLISE PARALELA                |
         |                                                          |
         |  +--------------------+  +----------------------------+  |
         |  |   External APIs    |  |       Internal Engines     |  |
         |  |   - VirusTotal v3  |  |   - CustomThreatFeed       |  |
         |  |   - AbuseIPDB      |  |   - YARA Rule Analyzer     |  |
         |  |   - AlienVault OTX |  |   - PEfile & Oletools      |  |
         |  |   - Shodan / IP    |  |   - Cuckoo Sandbox         |  |
         |  +---------+----------+  +--------------+-------------+  |
         +------------|----------------------------|----------------+
                      |                            |
                      +-------------+--------------+
                                    | [JSON Consolidados]
                                    v
                        +----------------------------+
                        |  PostgreSQL Database SSOT  | (Salva Resultados Integrados)
                        +------------+---------------+
                                    |
                                    | [Gera Evento / Alerta de Risco]
                                    v
               +--------------------+--------------------+
               |           DISPARO DE ALERTA             |
               |                                         |
               |  - SIEM / SOAR (Alertas JSON / Webhook) |
               |  - Painel UI React (Visualização Real)  |
               |  - Alertas Syslog / Security Operations |
               +-----------------------------------------+
```

### Explicação da Arquitetura Modular do IntelOwl

A flexibilidade e robustez do IntelOwl vêm de sua arquitetura baseada em plugins independentes:

1. **Analyzers (Analisadores):**
   * **O que são:** Os motores que executam a extração de dados reais sobre o IOC (tanto arquivos quanto observáveis).
   * **Tipos:**
     * **External:** APIs SaaS na nuvem (VirusTotal, AbuseIPDB, Shodan).
     * **Internal:** Ferramentas locais instaladas como bibliotecas Python ou em contêineres Docker adjacentes (YARA, Capa, Oletools, ClamAV, Thug, Sandboxes como Cuckoo ou Dragonfly).
2. **Ingestors (Ingestores):**
   * **O que são:** Componentes que automatizam a captação recorrente e contínua de ameaças a partir de feeds abertos ou comerciais (ex: Ransomware Tracker, Abuse.ch URLhaus, MISP Feeds). Eles alimentam o IntelOwl sem intervenção manual.
3. **Pivoters (Pivotadores):**
   * **O que são:** Conectores avançados que usam os resultados de uma análise concluída para encadear inteligentemente uma nova rodada de consultas (ex: se um domínio malicioso resolver para um IP suspeito, o Pivoter inicia uma varredura sobre esse IP automaticamente).
4. **Connectors (Conectores):**
   * **O que são:** Responsáveis por exportar os resultados consolidados para plataformas externas de compartilhamento de inteligência ou resposta a incidentes (ex: postar novos IOCs no MISP, sincronizar incidentes com OpenCTI, ou atualizar listas negras de Firewalls Palo Alto).
5. **Playbooks (Guias de Análise):**
   * **O que são:** Agrupamentos de analisadores configurados para serem disparados em conjunto. Isso otimiza o uso de chaves de API (ex: um playbook `Fast_IP_Check` roda apenas AbuseIPDB e Shodan; já um playbook `Deep_Malware_Check` roda Cuckoo, YARA e VirusTotal).

---

## 🐳 2. Infraestrutura & Deployment (`docker-compose.yml`)

Nossa arquitetura de deploy foi modelada para resiliência operacional, separando as tarefas rápidas (filas de rede e barramento) de tarefas de alta latência (varreduras estáticas de arquivos pesados e detonação em sandbox).

### Serviços Orquestrados no `docker-compose.yml`:
* **`db` (PostgreSQL 15):** Banco de dados relacional principal que serve como única fonte da verdade (SSOT) para jobs, relatórios históricos e tokens.
* **`redis` (Redis 7):** Broker de mensagens seguro do Celery e cache in-memory de sessões, configurado com persistência AOF (Append-Only File) e autenticação de senha complexa.
* **`web` (Django / Gunicorn):** O core REST API que processa e valida requisições, executa autenticações de tokens corporativos e interage com o banco de dados.
* **`celery_worker_observables`:** Worker Celery isolado para consultas rápidas de rede e reputação de IPs, URLs e domínios. Roda em paralelo com alta concorrência (`-c 4`).
* **`celery_worker_files`:** Worker de alta capacidade de CPU e memória destinado à descompactação de arquivos, checagem YARA pesada e análise estática ou dinâmica.
* **`celery_beat`:** Orquestrador periódico interno que agenda limpezas no banco e atualiza assinaturas locais de ameaças.
* **`nginx` (Reverse Proxy Hardened):** Proxy de borda configurado para terminação de TLS v1.2/v1.3, bloqueio de cabeçalhos inseguros (CSP, HSTS, X-Frame) e redirecionamento de tráfego inseguro.

### Como Iniciar o Ambiente:
```bash
# 1. Entre no diretório do projeto
cd intelowl-threat-intel/

# 2. Crie o arquivo de variáveis de ambiente com base no exemplo
cp .env.example .env

# 3. Ajuste as credenciais no .env
nano .env

# 4. Levante a stack completa em modo Daemon
docker-compose up -d

# 5. Verifique a saúde de todos os contêineres
docker-compose ps
```

---

## 🐍 3. Analisador Customizado (`custom_analyzer.py`)

Foi desenvolvida uma classe estritamente compatível com o core do IntelOwl: `CustomThreatFeedAnalyzer`. Ela estende a classe abstrata `ObservableAnalyzer` e implementa os métodos cruciais de setup e execução.

### Principais Diferenciais de Engenharia de Segurança:
* **Validação Sintática Rígida (Pre-flight Sanitization):** Utiliza expressões regulares compiladas para garantir que apenas IPs válidos e nomes de domínio FQDN sejam processados. Evita vazamento de chaves ou chamadas a payloads maliciosos contra o backend corporativo.
* **Resiliência e Timeout Defensivo:** Configura um timeout customizável para impedir que instabilidade no servidor de reputação congele o worker do Celery.
* **Camada de Mocking Inteligente:** Permite testes e validações locais de SecOps sem depender de chaves reais da API, bastando definir a flag `INTELOWL_TEST_MODE=true` no escopo do teste.

---

## 🤖 4. Automação & Script de Integração (`integration_client.py`)

Para permitir a integração contínua do pipeline com ferramentas de SOAR (ex: Shuffle, Splunk Phantom, Cortex XSOAR) e sistemas de monitoramento (SIEM), criamos o `integration_client.py`.

### Recursos Implementados:
* **Mecanismo de Polling Não-Bloqueante:** Submete o IOC e monitora assincronamente o status do Job através de requisições de estado até obter a resposta final do Celery.
* **Pontuação de Risco Dinâmica (Threat Score Engine):** Lê os reports gerados e unifica a avaliação de múltiplos analisadores em um Score ponderado acumulado de 0 a 100.
* **Disparo Automático de Alertas (Webhooks SIEM):** Caso o Score ultrapasse o limite de tolerância estabelecido (padrão: 70), emite um payload JSON detalhado via console em formato Syslog estruturado e dispara uma chamada webhook HTTP POST para o SOAR de mitigação automática.

### Demonstração Prática do Fluxo Automatizado:
```bash
# Executar a simulação de teste integrada local
python3 integration_client.py --test
```

### Exemplos de Chamadas de Produção:
```bash
# Analisar um IP suspeito utilizando o token do IntelOwl
python3 integration_client.py \
  --url "https://intelowl.suaempresa.com" \
  --token "SUA_API_TOKEN_DO_INTELOWL" \
  --observable "185.220.101.5" \
  --playbooks "custom_threat_feed_playbook" \
  --threshold 75

# Analisar um arquivo PDF suspeito
python3 integration_client.py \
  --url "https://intelowl.suaempresa.com" \
  --token "SUA_API_TOKEN_DO_INTELOWL" \
  --file "/home/soc/downloads/nota_fiscal.pdf" \
  --playbooks "file_deep_analysis"
```

---

## 📖 5. Playbook de Operação e Comandos de Manutenção

### A. Registro de Novos Analisadores via Painel Admin Django

Para disponibilizar e ativar o `CustomThreatFeedAnalyzer` no frontend do IntelOwl, execute as etapas a seguir:

1. **Acessar o Admin:** Navegue até `https://<SUA_URL_INTELOWL>/admin/` e faça login com a conta de superusuário do Django.
2. **Adicionar Parâmetro de Autenticação:**
   * Vá em **Api_App -> Parameters** (ou acesse `/admin/api_app/parameter/`).
   * Clique em `Add Parameter`.
   * **Name:** `CUSTOM_THREAT_FEED_KEY`
   * **Description:** API Secret key used for authenticating with the internal reputation feed engine.
   * **Is Secret:** Selecione `True` (para ocultar o valor no banco e mascará-lo na UI).
   * **Value:** Insira a chave da sua API e clique em `Save`.
3. **Registrar a Configuração do Analisador:**
   * Vá em **Analyzers_Manager -> AnalyzerConfigs** (ou `/admin/analyzers_manager/analyzerconfig/`).
   * Clique em `Add Analyzer Config`.
   * Preencha as propriedades fundamentais:
     * **Name:** `CustomThreatFeedAnalyzer`
     * **Python Module:** `custom_analyzer` (nome do arquivo python sem o `.py`)
     * **Class Name:** `CustomThreatFeedAnalyzer`
     * **Description:** Consulta a reputação de IP e Domínio no Threat Feed Corporativo.
     * **Supported Types:** `["ip", "domain"]`
     * **Is Active:** Marque como `True`.
     * **Parameters JSON / Config:**
       ```json
       {
         "api_url": "https://api.threatintel.internal/v1/reputation",
         "api_key_name": "CUSTOM_THREAT_FEED_KEY",
         "timeout": 15,
         "risk_threshold": 70
       }
       ```
   * Salve o registro. O novo analisador estará disponível para compor qualquer Playbook!

---

### B. Manutenção e Atualização de Assinaturas (YARA, Sigma)

Em uma operação DevSecOps madura, as regras de detecção YARA (para arquivos maliciosos) e Sigma/Yeti devem ser atualizadas diariamente. O IntelOwl possui tarefas agendadas nativas para isso.

```bash
# Atualização manual via console do contêiner django
docker-compose exec web python3 manage.py update_yara_signatures

# Alternativa: Configuração de Cronjob diário no host para baixar feeds Yara públicos (Florian Roth, Malpedia)
0 3 * * * docker-compose -f /opt/intelowl/docker-compose.yml exec -T web python3 manage.py update_yara_signatures >> /var/log/intelowl_signatures.log 2>&1
```

---

### C. Limpeza de Relatórios e Arquivos Antigos (Data Retention Compliance)

De acordo com políticas de privacidade e LGPD/GDPR, manter amostras de malware e relatórios indefinitely representa riscos de vazamento de dados. Utilize as ferramentas de faxina do Django integradas:

```bash
# 1. Comando nativo para expurgar reports e arquivos expirados do banco e disco (PostgreSQL e Volumes)
docker-compose exec web python3 manage.py clean_old_jobs --days 90

# 2. Configurar execução agendada automática (executada toda segunda-feira à meia-noite)
0 0 * * 1 docker-compose -f /opt/intelowl/docker-compose.yml exec -T web python3 manage.py clean_old_jobs --days 90 >> /var/log/intelowl_cleanup.log 2>&1
```

### D. Solução de Problemas (Troubleshooting de SecOps)

```bash
# Monitorar logs em tempo real dos Celery Workers (Análise assíncrona travada ou falhas de conexões)
docker-compose logs -f celery_worker_observables celery_worker_files

# Verificar gargalos ou lentidão nas filas de mensagens do Redis
docker-compose exec redis redis-cli -a "SuaSenhaAqui" info stats | grep -i keyspace_hits
```

---
*Manual desenvolvido de acordo com as diretrizes do IntelOwl Project, estruturado por Jules - Arquiteto de Cyber Threat Intelligence.*
