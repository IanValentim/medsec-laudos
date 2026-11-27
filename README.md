# MedSec — transferência segura de laudos

Projeto acadêmico em Python para demonstrar controles de segurança em uma comunicação cliente-servidor de transferência de laudos médicos.

> **Atenção à compatibilidade com a rubrica:** este repositório implementa o **MedSec**, não um Cofre de Senhas. Os papéis existentes são `medico` e `recepcionista`; o protocolo é TCP com TLS e JSON; não há aplicação cliente, API HTTP/HTTPS, JWT, banco de dados, UFW ou Fail2ban configurados. As diferenças são identificadas ao longo deste documento para não atribuir ao código funcionalidades que ele não possui.

## 1. Identificação do projeto e da equipe

- **Solução:** MedSec — transferência segura de laudos.
- **Integrantes:** Nyckson Lael De Melo e Ian Valentim de Melo Facó.
- **Disciplina:** PSE102A - Segurança da Informação.
- **Vídeo de demonstração:** *link pendente; será incluído após publicação com acesso liberado ao professor.*

## 2. Objetivo e cenário de uso

O projeto demonstra como proteger a transferência de laudos médicos entre um cliente autorizado e um servidor. O ativo protegido é o conteúdo clínico dos laudos, além de credenciais, chaves criptográficas e metadados associados.

Os perfis de acesso implementados são:

| Perfil | Permissões |
|---|---|
| `medico` | Enviar laudos, baixar laudos e listar status |
| `recepcionista` | Listar status |

O código **não implementa** os perfis `admin` e `leitor`, cadastro de contas por interface nem exclusão de segredos.

### Propriedades de segurança demonstradas

- **Confidencialidade:** TLS protege a conexão; AES-256-GCM protege o conteúdo do laudo armazenado em repouso. Os metadados e logs não são cifrados pelo aplicativo e podem conter nome de paciente.
- **Integridade:** a assinatura do conteúdo é validada com RSA-PSS/SHA-256 antes do armazenamento; AES-GCM detecta adulteração dos arquivos cifrados.
- **Autenticidade:** o servidor autentica usuários com senha e TOTP e valida a assinatura digital do laudo com uma chave pública confiável para a instalação.
- **Rastreabilidade:** eventos de autenticação, acesso, envio, download e falhas são registrados no terminal e em `logs/security_audit.log`. O log é local, não é protegido contra alteração e pode conter dados sensíveis; portanto, demonstra auditoria básica, não uma trilha inviolável.

Este é um projeto didático, não um sistema clínico pronto. Não utilize dados reais de pacientes.

## 3. Arquitetura, rede e tecnologias

### Nós e comunicação

O projeto consiste no processo servidor e em um cliente que precisa ser implementado separadamente. Eles se comunicam por uma conexão TCP protegida por TLS. O servidor recebe objetos JSON UTF-8 delimitados por `\n`.

```text
+-----------------------------+     TCP + TLS 1.2 ou superior     +-----------------------------+
| Cliente (não incluído)      | --------------------------------> | Servidor MedSec             |
| - valida certs/ca.crt        |          padrão: 8443/TCP         | - servidor.py               |
| - autentica com senha + TOTP| <-------------------------------- | - RBAC e validação de laudo |
| - assina conteúdo do laudo  |            respostas JSON          | - arquivos em dados/        |
+-----------------------------+                                    +-----------------------------+
                                                                       |
                                              logs/security_audit.log <-+
```

`8443/TCP` é a porta padrão do servidor. O protocolo **não é HTTPS**: não existe HTTP, FastAPI ou Flask neste repositório. `0.0.0.0` é o endereço de escuta padrão, isto é, o processo aceita conexões em todas as interfaces locais. Use firewall para limitar os clientes autorizados.

### Tecnologias e justificativa

| Tecnologia | Uso neste repositório |
|---|---|
| Python 3.10+ | Linguagem do servidor e do script de provisionamento |
| `socket`, `ssl`, `threading` (biblioteca padrão) | Servidor TCP, TLS e tratamento concorrente de conexões |
| `cryptography` | Criação de certificados/chaves, RSA-PSS, AES-256-GCM e operações criptográficas |
| `pyotp` | Geração e validação de códigos TOTP |
| `hashlib` (biblioteca padrão) | Hash de senha com PBKDF2-HMAC-SHA256 |

**Não são dependências nem componentes atuais:** FastAPI, Flask, PyJWT, OpenSSL como executável, banco de dados, `ufw` e Fail2ban. O script `setup_pki.py` gera certificados usando a biblioteca Python `cryptography`; não chama o comando OpenSSL. A defesa contra falhas e rajadas de conexões é um bloqueio temporário em memória dentro do processo, não uma regra de firewall nem uma integração com Fail2ban.

## 4. Pré-requisitos de ambiente

- Windows, Linux ou macOS com Python **3.10 ou superior**.
- PowerShell no Windows ou terminal shell no Linux/macOS.
- Dependências listadas em [`requirements.txt`](./requirements.txt).
- Para conexões entre computadores, conectividade de rede e liberação restrita da porta TCP escolhida.
- OpenSSL ou Wireshark são opcionais para inspeção manual de TLS; não são necessários para instalar ou executar o servidor.
- `ufw` e Fail2ban não são configurados pelo projeto. Em um host Linux, as regras de firewall e os serviços de proteção precisam ser administrados separadamente.

## 5. Estrutura do repositório

```text
.
├── certs/
│   ├── ca.crt                 # Certificado público da CA (presente no repositório)
│   ├── medico_sign.pub        # Chave pública de verificação (presente no repositório)
│   └── servidor.crt           # Certificado TLS público (presente no repositório)
├── requirements.txt           # cryptography e pyotp
├── servidor.py                # Servidor TCP/TLS, autenticação e operações de laudo
├── setup_pki.py               # Provisiona certificados, chaves e contas iniciais
└── .gitignore                 # Ignora ambiente virtual, dados, logs e arquivos *.key
```

O provisionamento cria arquivos locais ignorados pelo Git:

```text
certs/
├── ca.key                     # Chave privada da autoridade certificadora
├── servidor.key               # Chave privada TLS do servidor
└── medico_sign.key            # Chave privada para assinar laudos
dados/
├── aes_repouso.key            # Chave AES-256 dos laudos
├── usuarios.json              # Hashes de senha e segredos TOTP
└── laudos/                    # Arquivos .enc e metadados .meta.json
logs/
└── security_audit.log         # Eventos em formato JSON Lines
```

Não existem neste repositório as pastas `server/`, `client/` ou `scripts/`, nem o arquivo `.env.example`. As configurações do servidor são passadas por argumentos de linha de comando (`--host` e `--port`), e os caminhos de certificados e dados são relativos à pasta atual.

## 6. Instalação e configuração

### Obter o código

Se ainda não tiver uma cópia local, clone o repositório usando a URL fornecida pela equipe ou pelo professor:

```bash
git clone <URL_DO_REPOSITORIO>
cd medsec-laudos-main
```

Se os arquivos já estiverem no computador, abra o terminal na raiz do projeto e ignore o passo de clone.

### Windows (PowerShell)

```powershell
py --version
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Não é necessário ativar o ambiente virtual. Executar `.\.venv\Scripts\python.exe` diretamente evita problemas com a política de execução do PowerShell.

Opcionalmente, ative-o:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Linux/macOS

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

### Gerar certificados, chaves e contas

Execute o setup somente em uma instalação nova:

```powershell
.\.venv\Scripts\python.exe setup_pki.py
```

No Linux/macOS:

```bash
.venv/bin/python setup_pki.py
```

O comando pergunta quais IPs devem constar no certificado TLS. Pressione Enter para incluir somente `127.0.0.1`, ou digite os IPs separados por vírgula. Também é possível informar IPs na linha de comando:

```powershell
.\.venv\Scripts\python.exe setup_pki.py --ip 192.168.1.25 10.8.0.5
```

O script cria certificados e chaves localmente com `cryptography`; não é necessário gerar certificados via OpenSSL. Ele também cria duas contas e imprime as credenciais e segredos/URIs TOTP no terminal. Guarde essas informações em local seguro e configure um aplicativo autenticador.

> **Não rode o setup novamente sem backup e planejamento.** A cada execução, ele substitui certificados e chaves, chave AES, usuários e segredos TOTP. A substituição da chave AES impede a leitura dos laudos anteriormente cifrados; a substituição de credenciais e certificados também invalida cópias anteriores.

### `.env`, firewall e Fail2ban

Não há arquivo `.env` nem carregamento de variáveis de ambiente no código atual. Host e porta são configurados por `--host` e `--port`.

O projeto não habilita nem configura `ufw` ou Fail2ban. Em um servidor Linux, um administrador pode limitar a porta à rede/IP do cliente, por exemplo:

```bash
sudo ufw allow from <IP_DO_CLIENTE> to any port 8443 proto tcp
sudo ufw status
```

Revise as regras existentes antes de habilitar ou alterar um firewall remoto para evitar perder acesso ao host. Esse exemplo é uma configuração externa ao projeto; ele não configura Fail2ban e não deve ser interpretado como uma integração implementada.

## 7. Execução e fluxo de uso

### Iniciar o servidor

Na raiz do projeto, no Windows:

```powershell
.\.venv\Scripts\python.exe servidor.py --host 127.0.0.1 --port 8443
```

Para aceitar conexões pela rede/VPN, o host pode escutar em todas as interfaces:

```powershell
.\.venv\Scripts\python.exe servidor.py --host 0.0.0.0 --port 8443
```

No Linux/macOS, substitua o executável por `.venv/bin/python`. Para encerrar, pressione `Ctrl+C`.

O servidor precisa dos arquivos gerados em `certs/` e `dados/`. Execute o comando da pasta raiz. O cliente deve confiar em `certs/ca.crt` e conectar usando um IP/nome incluído no certificado.

### Cliente e fluxo de uso

**Este repositório não contém um programa cliente.** Portanto, não há comando para executar um cliente nem uma tela de cadastro/login. Um cliente compatível precisa implementar TLS, validação do certificado, mensagens JSON terminadas em `\n`, assinatura RSA-PSS e as ações listadas abaixo.

As contas existentes são provisionadas estaticamente por `setup_pki.py`:

| Usuário | Papel | Permissões |
|---|---|---|
| `dr_silva` | `medico` | Enviar, baixar e listar status |
| `recep_ana` | `recepcionista` | Listar status |

As senhas estão definidas no código de setup e são exibidas durante a geração. São credenciais demonstrativas e não devem ser usadas em produção. O login requer senha e token TOTP. O servidor não gera JWT: a sessão autenticada permanece associada à conexão TLS atual.

O protocolo aceita uma mensagem JSON por linha; limite de 1 MiB por mensagem:

| `acao` | Campos adicionais | Resultado |
|---|---|---|
| `LOGIN` | `usuario`, `senha`, `totp` | Autentica o usuário na conexão |
| `ENVIAR_LAUDO` | `paciente`, `conteudo`, `assinatura_b64` | Verifica assinatura e armazena o conteúdo cifrado |
| `LISTAR_STATUS` | — | Retorna metadados, sem conteúdo clínico |
| `BAIXAR_LAUDO` | `laudo_id` | Decifra e retorna o laudo autorizado |
| `SAIR` | — | Encerra a conexão |

Exemplo de requisição de login:

```json
{"acao":"LOGIN","usuario":"dr_silva","senha":"<senha>","totp":"<codigo-atual>"}
```

Para enviar, `assinatura_b64` deve conter a assinatura RSA-PSS/SHA-256 dos bytes UTF-8 exatos de `conteudo`, feita com `certs/medico_sign.key`. O servidor verifica usando `certs/medico_sign.pub`. Não existe ação para excluir um laudo.

As respostas contêm `ok` e `codigo`. Entre os códigos usados estão `200`, `400`, `401`, `403`, `404`, `429` e `500`.

## 8. Roteiro de reprodução e validação

Faça as verificações somente em uma instalação local/isolada, com dados fictícios. Não há suíte de testes automatizados ou scripts de força bruta no repositório.

### RA1 — RBAC e MFA

1. Inicie o servidor localmente em `127.0.0.1:8443`.
2. Conecte com um cliente compatível e autentique como `recep_ana` usando sua senha e código TOTP.
3. Envie uma requisição `ENVIAR_LAUDO` de teste. O servidor deve responder `403` (`ACESSO_NEGADO`), porque o papel `recepcionista` só pode listar status. A ação “excluir segredo” da rubrica não existe neste projeto.
4. Em uma nova conexão, tente `LOGIN` com senha correta e código TOTP inválido. O servidor deve responder `401` (`CREDENCIAIS_INVALIDAS`).
5. Confira os eventos `RBAC_ACESSO_NEGADO` e `LOGIN_NEGADO` no terminal e em `logs/security_audit.log`.

Não há cliente implementado para executar esses passos. Uma ferramenta de teste precisa validar o certificado da CA e respeitar o protocolo JSON sobre TLS.

### RA2 — Criptografia em repouso e em trânsito

**Em repouso:** após enviar um laudo fictício válido, confira `dados/laudos/`. O arquivo `.enc` contém nonce e ciphertext do AES-256-GCM; o `.meta.json` contém metadados em texto JSON e, portanto, não deve ser confundido com o conteúdo cifrado. O projeto não usa banco de dados.

No PowerShell:

```powershell
Get-ChildItem .\dados\laudos\
Format-Hex .\dados\laudos\<ID_DO_LAUDO>.enc
Get-Content .\dados\laudos\<ID_DO_LAUDO>.meta.json
```

**Em trânsito:** capture apenas o tráfego do seu ambiente de teste com Wireshark, usando o filtro `tcp.port == 8443`, e observe o handshake TLS e os registros cifrados. A captura não deve revelar o JSON em texto claro. Em Linux, uma captura restrita à interface local pode ser gravada para análise:

```bash
sudo tcpdump -i lo -nn -s0 -w medsec-teste.pcap 'tcp port 8443'
```

Abra `medsec-teste.pcap` no Wireshark e examine o tráfego TLS. Pare a captura ao finalizar e não publique arquivos de captura que possam conter dados ou metadados sensíveis.

### RA3 — Defesa e monitoramento

O servidor possui um bloqueio temporário interno, em memória: quatro falhas contabilizadas em uma janela de 60 segundos podem bloquear o IP por 120 segundos; mais de 20 conexões na janela também podem resultar em bloqueio. O código não executa um script de força bruta, não cria regras no firewall e não integra com Fail2ban.

Para testar manualmente em loopback:

1. Use somente `127.0.0.1` e uma conta fictícia de teste.
2. Faça até quatro tentativas de login com código TOTP inválido, em conexões TLS de teste.
3. Confira a resposta de bloqueio (`429`, `IP_BLOQUEADO`) e o evento `[IDS/IPS ALERT] IP_BLOQUEADO` no terminal e em `logs/security_audit.log`.
4. Aguarde o período de bloqueio antes de repetir. O estado é mantido somente em memória e desaparece quando o servidor reinicia.

Não há script de teste automatizado, regra Fail2ban ou bloqueio persistente no firewall para reproduzir. Para evidenciar Fail2ban especificamente, seria necessário implementar e configurar essa integração separadamente.

### Conformidade ética e legal

Testes de autenticação, bloqueio e captura de pacotes devem ser realizados exclusivamente em ambiente isolado e autorizado pela equipe, com contas fictícias e conteúdo de teste. Não teste endereços, serviços ou redes de terceiros. Não use, grave ou compartilhe dados reais de saúde. A equipe deve revisar e observar a legislação e as políticas institucionais aplicáveis, incluindo a LGPD, antes de qualquer tratamento de dados pessoais.

## 9. Segurança, armazenamento e limitações

- O TLS exige versão mínima 1.2.
- Senhas são armazenadas como hashes PBKDF2-HMAC-SHA256 com salt, não em texto claro no arquivo de usuários.
- O conteúdo do laudo só é armazenado depois da verificação da assinatura e é cifrado com AES-256-GCM; a chave de 32 bytes fica em `dados/aes_repouso.key`.
- O nonce GCM é armazenado junto ao ciphertext, e o ID do laudo é usado como dado autenticado adicional.
- Metadados podem expor nome de paciente. Proteja `dados/`, `logs/` e backups com permissões adequadas.
- O bloqueio IDS/IPS é local ao processo e não persiste após reinicialização.
- O `.gitignore` exclui chaves privadas (`certs/*.key`), dados, logs e `.venv/`. Verifique o estado do repositório antes de compartilhar arquivos.
- Nunca compartilhe `certs/ca.key`, `certs/servidor.key`, `certs/medico_sign.key`, `dados/aes_repouso.key`, `dados/usuarios.json`, laudos ou logs.
- Sem `dados/aes_repouso.key`, não será possível decifrar os laudos de backup.

O projeto não implementa cliente, JWT, API HTTP, banco de dados, gestão de usuários, recuperação/troca de senha, rotação automatizada de chaves, Fail2ban, gestão de firewall, retenção de dados ou trilha de auditoria inviolável. A utilização em produção exigiria implementação e revisão de segurança, privacidade, conformidade, operação e infraestrutura.
