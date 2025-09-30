# Analyze Logs — Ferramenta simples para análise de access.log

**Descrição**  
Script Python para análise rápida de logs web (formato Combined/CLF). Lê `.log` ou `.log.gz` e gera um relatório com:
- distribuição de campos (NF),
- tabela de códigos HTTP por IP,
- top IPs por volume,
- top IPs que tentaram `POST /login`,
- endpoints mais acessados por IP (endpoints por IP),
- snippets de contexto para IPs suspeitos,
- sugestões de comandos para bloqueio (iptables / fail2ban).

O objetivo é fornecer um **relatório automático** que facilite investigação de brute-force, scans e acessos suspeitos.

---

## Requisitos
- Python 3.7+ (sem bibliotecas externas)
- Acesso ao arquivo de log (p.ex. `access.log` ou `access.log.gz`)

---

## Instalação (opções rápidas)

### Termux (Android)
```bash
pkg update && pkg upgrade -y
pkg install python git -y

Linux / macOS

# Debian/Ubuntu
sudo apt update
sudo apt install python3 git -y

# macOS (Homebrew)
brew install python git

Windows

Recomendo usar WSL (Ubuntu) ou Git Bash. Caso contrário, use um ambiente Python para rodar o script (p.ex. Pythont IDLE / Pydroid no Android).


---


Como rodar (passo a passo)

1. Coloque o arquivo analyze_logs_full.py na pasta desejada (ou clone o repo).


2. Abra terminal na pasta do script.


3. (Opcional) Tornar executável:



chmod +x analyze_logs_full.py

4. Executar o script:



python3 analyze_logs_full.py

> o script perguntará pelo caminho do arquivo de log:



Path to log file (e.g. access.log or access.log.gz) >

Digite o caminho e pressione Enter. Exemplos:

/sdcard/Download/access.log (Android/Termux)

/storage/emulated/0/Download/access.log (alguns Android)

/var/log/nginx/access.log (Linux servidor)

/home/usuario/meus-logs/access.log.gz (arquivo comprimido suportado)


5. O script roda automaticamente e imprime o relatório no terminal (HEAD, distribuição de campos, tabela HTTP status por IP, top IPs, endpoints por IP, contexto do IP suspeito, sugestão de bloqueio).


6. Salvar saída em arquivo (opções):



Redirecionar para arquivo:


python3 analyze_logs_full.py > relatorio.txt

Salvar com data/hora (bash):


python3 analyze_logs_full.py | tee relatorio_$(date +%F_%H%M%S).txt

No Windows PowerShell:

python analyze_logs_full.py | Tee-Object relatorio_$(Get-Date -Format "yyyy-MM-dd_HHmmss").txt


---

Exemplo de uso (simples)

python3 analyze_logs_full.py
# quando pedir:
# Path to log file (e.g. access.log or access.log.gz) > /sdcard/Download/access.log

Saída esperada (resumida):

PRIMEIRAS LINHAS (head)

Distribuição de campos (NF)

=== Top IPs ===

=== HTTP Status per IP === (tabela com 200, 401, 404, etc.)

=== Top POST /login IPs ===

=== Endpoints por IP (top N) ===

Context snippets para o IP suspeito e comandos sugeridos (iptables / fail2ban)



---

Observações e boas práticas

O script não altera firewall nem bane IPs automaticamente — ele sugere comandos de bloqueio que você pode executar manualmente.

Para produção, prefira automatizar via fail2ban ou WAF em vez de bans manuais.

Tenha atenção com arquivos muito grandes: em dispositivos com pouca RAM rode amostras ou use ferramentas especializadas (ELK, Graylog, etc.).

Se o log usar formato customizado, a regex do script pode precisar de ajuste.



