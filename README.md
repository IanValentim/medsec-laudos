# MedSec - Transferencia Segura de Laudos Medicos

Projeto final da disciplina de Seguranca da Informacao (PSE102A - PUCPR). Implementa comunicacao cliente-servidor em Python 3.12 sobre rede IP real para envio, armazenamento e consulta de laudos medicos, cobrindo controles de autenticacao, autorizacao, criptografia em transito/repouso e deteccao/bloqueio de intrusao.

## Estrutura do Projeto

- `setup_pki.py`: gera a Autoridade Certificadora interna (`ca.crt` / `ca.key`), o certificado TLS do servidor com IPs no SAN (`servidor.crt` / `servidor.key`), o par RSA de assinatura do medico (`medico_sign.key` / `medico_sign.pub`), a chave AES-256 para cifragem em repouso (`dados/aes_repouso.key`) e a base inicial de usuarios (`dados/usuarios.json`).
- `servidor.py`: servidor TCP/TLS multithread com autenticacao PBKDF2 + TOTP, RBAC, verificacao de assinatura RSA-PSS, cifragem AES-256-GCM em repouso, IDS/IPS com blacklist temporaria e auditoria em `logs/security_audit.log`.
- `cliente.py`: cliente TLS interativo que valida o certificado do servidor contra `certs/ca.crt`, autentica usuario/senha/TOTP e assina laudos com `certs/medico_sign.key`.
- `testes_ataque.py`: suite automatizada com os 4 casos de validacao (`T01` a `T04`).
- `requirements.txt`: dependencias do projeto (`cryptography` e `pyotp`).
- `.gitignore`: impede o versionamento de chaves privadas (`certs/*.key`), `dados/`, `logs/` e `.venv/`.

## Controles Implementados (RA1, RA2 e RA3)

### RA1 - Identificacao, Autenticacao e Controle de Acesso
- **Hash de senha:** `PBKDF2-HMAC-SHA256` com `600.000` iteracoes, salt aleatorio de 16 bytes por usuario e comparacao em tempo constante via `hmac.compare_digest`.
- **Segundo fator (2FA):** TOTP compativel com RFC 6238 (`pyotp`, tolerancia `valid_window=1` para leve diferenca de relogio).
- **RBAC no servidor:**
  - `medico` (`dr_silva`): autorizado para `ENVIAR_LAUDO`, `BAIXAR_LAUDO` e `LISTAR_STATUS`.
  - `recepcionista` (`recep_ana`): autorizado apenas para `LISTAR_STATUS` (retorna `403 ACESSO_NEGADO` em envio e download).

### RA2 - Criptografia em Transito, Integridade e Repouso
- **Canal seguro (TLS):** socket TCP protegido com `ssl` (minimo TLS 1.2) e validacao estrita de cadeia X.509 e `SubjectAlternativeName` (IP real da VPN + `127.0.0.1`).
- **Assinatura digital:** laudos assinados no cliente com `RSA-PSS` + `SHA-256` (`certs/medico_sign.key`) e validados pelo servidor (`certs/medico_sign.pub`) antes de serem aceitos.
- **Cifragem em repouso:** conteudo salvo em `dados/laudos/<ID>.enc` cifrado com `AES-256-GCM`, nonce unico de 12 bytes por arquivo e `laudo_id` como AAD. Metadados ficam separados em `<ID>.meta.json`.

### RA3 - Deteccao de Intrusao, Prevencao e Auditoria
- **IDS/IPS integrado:** monitora falhas por IP em janela deslizante de 60 segundos (`LOGIN_FALHO`, `PAYLOAD_MALFORMADO`, `TLS_FALHA`, `NAO_AUTENTICADO`, `ACAO_INVALIDA`, `ACAO_DESCONHECIDA`, `LAUDO_INCOMPLETO`) e rajadas de conexoes (>20 conexoes em 60s).
- **Blacklist automatica:** ao atingir 4 falhas em 60s (ou exceder o limite de conexoes), bloqueia o IP por 120 segundos, retornando `429 IP_BLOQUEADO` e recusando novas conexoes imediatamente.
- **Auditoria:** eventos gravados em formato JSON Lines em `logs/security_audit.log` e exibidos no terminal do servidor.

## Pre-requisitos e Instalacao (Windows / Python 3.12)

Em cada PC (Servidor e Cliente):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configuracao e Execucao em Rede Real (2 PCs via VPN)

### 1. Provisionamento inicial (apenas no PC Servidor)

Informe o IP real do servidor na VPN (ex.: Radmin VPN `26.x.x.x`) para inclui-lo no SAN do certificado TLS:

```powershell
python setup_pki.py --ip <IP_VPN_DO_SERVIDOR>
```

Ao final, anote os `TOTP secret` gerados para `dr_silva` (senha padrao `Medico@2026`) e `recep_ana` (senha padrao `Recep@2026`).

### 2. Liberacao de firewall (apenas no PC Servidor)

Em PowerShell como Administrador, libere a porta `8443/TCP` restrita a sub-rede da VPN (exemplo Radmin `26.0.0.0/8`):

```powershell
New-NetFirewallRule -DisplayName "MedSec TLS Server 8443" -Direction Inbound -Protocol TCP -LocalPort 8443 -RemoteAddress 26.0.0.0/8 -Action Allow
```

### 3. Arquivos necessarios no PC Cliente

Copie para o PC do colega apenas:
- `cliente.py`, `testes_ataque.py` e `requirements.txt`
- `certs/ca.crt` (para validar o certificado do servidor)
- `certs/medico_sign.key` (para assinar laudos enviados como medico)

Nao copie `certs/ca.key`, `certs/servidor.key`, `dados/aes_repouso.key` nem `dados/usuarios.json` para o PC cliente.

### 4. Subir o Servidor

```powershell
python servidor.py --host 0.0.0.0 --port 8443
```

### 5. Rodar o Cliente Interativo

Teste local:

```powershell
python cliente.py
```

Teste remoto pela VPN:

```powershell
python cliente.py --host <IP_VPN_DO_SERVIDOR> --port 8443
```

Para gerar o token TOTP de 6 digitos no terminal durante o login:

```powershell
python -c "import pyotp; print(pyotp.TOTP('<TOTP_SECRET>').now())"
```

## Casos de Teste Automatizados (`testes_ataque.py`)

O script executa quatro cenarios de validacao:
- `T01`: Login como `recep_ana`, consulta de status (`200`) e bloqueio RBAC (`403 ACESSO_NEGADO`) ao tentar enviar ou baixar laudos.
- `T02`: Envio legitimo de laudo assinado por `dr_silva` em canal TLS, cifragem AES-256-GCM em repouso e download com verificacao de integridade.
- `T03`: Adulteracao do texto de um laudo apos a assinatura RSA-PSS, rejeitado pelo servidor com `400 ASSINATURA_INVALIDA`.
- `T04`: Disparo de tentativas invalidas de login ate o bloqueio `429 IP_BLOQUEADO` e confirmacao de recusa imediata de nova conexao pela blacklist.

Execucao local (le os segredos TOTP automaticamente de `dados/usuarios.json`):

```powershell
python testes_ataque.py
```

Execucao remota a partir do PC Cliente:

```powershell
python testes_ataque.py --host <IP_VPN_DO_SERVIDOR> --port 8443 --totp-medico <TOTP_SECRET_MEDICO> --totp-recep <TOTP_SECRET_RECEP>
```

Para executar apenas um caso especifico (por exemplo, `T02` durante captura no Wireshark com filtro `tcp.port == 8443`):

```powershell
python testes_ataque.py --host <IP_VPN_DO_SERVIDOR> --port 8443 --totp-medico <TOTP_SECRET_MEDICO> --teste T02
```

Nota: o teste `T04` bloqueia o IP de origem por 120 segundos no servidor. Para reexecutar testes logo apos o `T04`, aguarde 120s ou reinicie `servidor.py`.
