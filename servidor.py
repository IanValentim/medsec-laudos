"""Servidor TLS para transferencia segura de laudos medicos (RA1, RA2 e RA3)."""

import argparse
import base64
import binascii
from datetime import datetime, timezone
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import threading
import time

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

CERT_SERVIDOR = Path("certs/servidor.crt")
CHAVE_SERVIDOR = Path("certs/servidor.key")
CHAVE_PUB_MEDICO = Path("certs/medico_sign.pub")
ARQUIVO_AES = Path("dados/aes_repouso.key")
ARQUIVO_USUARIOS = Path("dados/usuarios.json")
DIR_LAUDOS = Path("dados/laudos")
DIR_LOGS = Path("logs")
ARQUIVO_LOG = DIR_LOGS / "security_audit.log"

# Handshake TLS curto bloqueia conexoes travadas (Slowloris); sessao ativa tolera pausa humana no menu.
TIMEOUT_HANDSHAKE = 10.0
TIMEOUT_CONEXAO = 120.0
# Limite de 1 MB por mensagem JSON protege contra exaustao de memoria.
MAX_TAMANHO_MSG = 1024 * 1024

# Janela deslizante do IDS/IPS para detectar forca bruta e rajadas de conexoes.
IDS_JANELA_SEGUNDOS = 60
IDS_MAX_FALHAS = 4
IDS_MAX_CONEXOES_JANELA = 20
IDS_TEMPO_BLOQUEIO = 120

# Aceita apenas o padrao gerado pelo servidor para evitar Path Traversal em downloads.
REGEX_LAUDO_ID = re.compile(r"^[A-Z0-9-]+$")

# Matriz de controle de acesso baseado em papel (RBAC).
PERMISSOES_RBAC = {
    "medico": {"ENVIAR_LAUDO", "BAIXAR_LAUDO", "LISTAR_STATUS"},
    "recepcionista": {"LISTAR_STATUS"},
}

lock_ids = threading.Lock()
lock_log = threading.Lock()
ips_bloqueados: dict[str, float] = {}
falhas_por_ip: dict[str, list[float]] = {}
conexoes_por_ip: dict[str, list[float]] = {}


def registrar_evento(
    nivel: str,
    evento: str,
    ip: str,
    mensagem_console: str,
    usuario: str | None = None,
    detalhes: dict | None = None,
) -> None:
    """Imprime evento legivel no terminal e grava registro JSON Lines em logs/security_audit.log."""
    hora_local = datetime.now().strftime("%H:%M:%S")
    print(f"[{hora_local}] [{nivel}] [{evento}] {mensagem_console}", flush=True)

    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nivel": nivel,
        "evento": evento,
        "ip": ip,
        "usuario": usuario,
        "detalhes": detalhes or {},
    }
    with lock_log:
        DIR_LOGS.mkdir(parents=True, exist_ok=True)
        with ARQUIVO_LOG.open("a", encoding="utf-8") as arquivo:
            arquivo.write(json.dumps(registro, ensure_ascii=False) + "\n")


def tempo_restante_bloqueio(ip: str) -> int:
    """Retorna segundos restantes na blacklist temporaria, ou 0 se o IP estiver liberado."""
    agora = time.monotonic()
    with lock_ids:
        expira_em = ips_bloqueados.get(ip)
        if expira_em is None:
            return 0
        restante = expira_em - agora
        if restante <= 0:
            del ips_bloqueados[ip]
            return 0
        return max(1, int(restante))


def registrar_conexao_ip(ip: str) -> bool:
    """Monitora taxa de conexoes por IP (rate limiting) e bloqueia rajadas suspeitas."""
    agora = time.monotonic()
    corte = agora - IDS_JANELA_SEGUNDOS
    with lock_ids:
        historico = [t for t in conexoes_por_ip.get(ip, []) if t >= corte]
        historico.append(agora)
        conexoes_por_ip[ip] = historico
        if len(historico) > IDS_MAX_CONEXOES_JANELA:
            ips_bloqueados[ip] = agora + IDS_TEMPO_BLOQUEIO
            conexoes_por_ip.pop(ip, None)
            return True
        return False


def registrar_falha_ip(ip: str, motivo: str) -> tuple[bool, int]:
    """Contabiliza falhas por IP na janela deslizante e ativa blacklist ao atingir o limite."""
    agora = time.monotonic()
    corte = agora - IDS_JANELA_SEGUNDOS
    with lock_ids:
        historico = [t for t in falhas_por_ip.get(ip, []) if t >= corte]
        historico.append(agora)
        total = len(historico)
        if total >= IDS_MAX_FALHAS:
            ips_bloqueados[ip] = agora + IDS_TEMPO_BLOQUEIO
            falhas_por_ip.pop(ip, None)
            return True, total
        falhas_por_ip[ip] = historico
        return False, total


def carregar_recursos() -> tuple[dict, bytes, object]:
    """Carrega usuarios, chave simetrica de repouso e chave publica RSA do medico."""
    obrigatorios = [
        CERT_SERVIDOR,
        CHAVE_SERVIDOR,
        CHAVE_PUB_MEDICO,
        ARQUIVO_AES,
        ARQUIVO_USUARIOS,
    ]
    faltando = [str(caminho) for caminho in obrigatorios if not caminho.exists()]
    if faltando:
        raise FileNotFoundError(
            "Arquivos obrigatorios ausentes ("
            + ", ".join(faltando)
            + "). Execute antes: python setup_pki.py"
        )

    usuarios = json.loads(ARQUIVO_USUARIOS.read_text(encoding="utf-8"))
    if not isinstance(usuarios, dict):
        raise ValueError("dados/usuarios.json deve conter um objeto JSON.")

    chave_aes = ARQUIVO_AES.read_bytes()
    if len(chave_aes) != 32:
        raise ValueError("dados/aes_repouso.key deve ter exatamente 32 bytes (AES-256).")

    chave_pub_medico = serialization.load_pem_public_key(CHAVE_PUB_MEDICO.read_bytes())
    DIR_LAUDOS.mkdir(parents=True, exist_ok=True)
    return usuarios, chave_aes, chave_pub_medico


def criar_contexto_tls() -> ssl.SSLContext:
    """Configura contexto TLS do servidor exigindo TLS 1.2 ou superior."""
    contexto = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Bloqueia versoes legadas (SSLv3, TLS 1.0 e 1.1) vulneraveis a ataques conhecidos.
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.load_cert_chain(certfile=str(CERT_SERVIDOR), keyfile=str(CHAVE_SERVIDOR))
    return contexto


def enviar_json(conn: ssl.SSLSocket, payload: dict) -> None:
    """Envia objeto JSON terminado por quebra de linha no canal TLS."""
    dados = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    conn.sendall(dados)


def receber_json(conn: ssl.SSLSocket, buffer: bytearray) -> dict | None:
    """Le uma mensagem JSON delimitada por '\n', validando tamanho maximo."""
    while b"\n" not in buffer:
        chunk = conn.recv(4096)
        if not chunk:
            if not buffer:
                return None
            raise ValueError("Conexao encerrada com payload incompleto.")
        buffer.extend(chunk)
        if len(buffer) > MAX_TAMANHO_MSG:
            raise ValueError("Mensagem excede o limite maximo de 1 MB.")

    indice_quebra = buffer.index(b"\n")
    linha = bytes(buffer[:indice_quebra])
    del buffer[: indice_quebra + 1]

    objeto = json.loads(linha.decode("utf-8"))
    if not isinstance(objeto, dict):
        raise ValueError("Payload JSON deve ser um objeto.")
    return objeto


def autenticar_usuario(
    usuarios: dict, usuario: str, senha: str, codigo_totp: str
) -> tuple[bool, str | None, str]:
    """Valida senha (PBKDF2-HMAC-SHA256 em tempo constante) e token 2FA TOTP."""
    registro = usuarios.get(usuario)
    if not isinstance(registro, dict):
        return False, None, "usuario_inexistente"

    try:
        salt = bytes.fromhex(registro["salt"])
        iteracoes = int(registro["iterations"])
        hash_esperado = registro["password_hash"]
        totp_secret = registro["totp_secret"]
        role = registro["role"]
    except (KeyError, ValueError, TypeError):
        return False, None, "cadastro_invalido"

    hash_calculado = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), salt, iteracoes
    ).hex()

    # compare_digest evita ataques de temporizacao (timing attack) na comparacao de hashes.
    if not hmac.compare_digest(hash_calculado, hash_esperado):
        return False, None, "senha_incorreta"

    # valid_window=1 tolera ate 30s de diferenca de relogio entre os dois PCs Windows.
    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(str(codigo_totp).strip(), valid_window=1):
        return False, None, "totp_invalido"

    return True, role, "ok"


def verificar_assinatura_laudo(
    chave_pub_medico, conteudo: str, assinatura_b64: str
) -> bool:
    """Valida assinatura RSA-PSS + SHA-256 garantindo autenticidade e integridade do laudo."""
    try:
        assinatura = base64.b64decode(assinatura_b64.encode("ascii"), validate=True)
        chave_pub_medico.verify(
            assinatura,
            conteudo.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, binascii.Error, ValueError, UnicodeEncodeError):
        return False


def salvar_laudo_cifrado(
    chave_aes: bytes, medico: str, paciente: str, conteudo: str
) -> dict:
    """Cifra o laudo com AES-256-GCM e grava em repouso junto aos metadados."""
    agora = datetime.now(timezone.utc)
    laudo_id = f"LAUDO-{agora.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"

    # Nonce unico de 96 bits por arquivo evita reutilizacao de keystream no modo GCM.
    nonce = secrets.token_bytes(12)
    # AAD vincula o texto cifrado ao laudo_id, impedindo troca de arquivo sem deteccao.
    aad = laudo_id.encode("utf-8")
    texto_cifrado = AESGCM(chave_aes).encrypt(nonce, conteudo.encode("utf-8"), aad)

    (DIR_LAUDOS / f"{laudo_id}.enc").write_bytes(nonce + texto_cifrado)

    metadados = {
        "laudo_id": laudo_id,
        "paciente": paciente,
        "medico": medico,
        "criado_em": agora.isoformat(),
        "status": "RECEBIDO_E_CIFRADO",
        "algoritmo_repouso": "AES-256-GCM",
        "assinatura_verificada": True,
    }
    (DIR_LAUDOS / f"{laudo_id}.meta.json").write_text(
        json.dumps(metadados, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return metadados


def listar_status_laudos() -> list[dict]:
    """Retorna apenas metadados de status dos laudos, sem expor conteudo clinico."""
    itens: list[dict] = []
    for caminho in DIR_LAUDOS.glob("*.meta.json"):
        try:
            meta = json.loads(caminho.read_text(encoding="utf-8"))
            if isinstance(meta, dict):
                itens.append(meta)
        except (OSError, json.JSONDecodeError):
            continue
    itens.sort(key=lambda item: item.get("criado_em", ""))
    return itens


def carregar_laudo_decifrado(chave_aes: bytes, laudo_id: str) -> dict | None:
    """Valida o ID, decifra o laudo AES-256-GCM em repouso e verifica sua tag de autenticacao."""
    if not REGEX_LAUDO_ID.fullmatch(laudo_id):
        raise ValueError("ID de laudo invalido.")

    caminho_enc = DIR_LAUDOS / f"{laudo_id}.enc"
    caminho_meta = DIR_LAUDOS / f"{laudo_id}.meta.json"
    if not caminho_enc.exists() or not caminho_meta.exists():
        return None

    bruto = caminho_enc.read_bytes()
    if len(bruto) < 28:
        raise ValueError("Arquivo cifrado corrompido.")

    nonce = bruto[:12]
    ciphertext = bruto[12:]
    texto_plano = AESGCM(chave_aes).decrypt(
        nonce, ciphertext, laudo_id.encode("utf-8")
    )
    metadados = json.loads(caminho_meta.read_text(encoding="utf-8"))
    metadados["conteudo"] = texto_plano.decode("utf-8")
    return metadados


def notificar_falha_e_ids(
    conn_tls: ssl.SSLSocket | None, ip: str, motivo: str, detalhes: dict
) -> bool:
    """Registra falha no IDS; se atingir o limite, bloqueia o IP e avisa no log e console."""
    bloqueou, total = registrar_falha_ip(ip, motivo)
    if bloqueou:
        registrar_evento(
            "ALERT",
            "[IDS/IPS ALERT] IP_BLOQUEADO",
            ip,
            f"IP {ip} BLOQUEADO por {IDS_TEMPO_BLOQUEIO}s ({total} falhas em {IDS_JANELA_SEGUNDOS}s; motivo={motivo})",
            detalhes={"motivo": motivo, "falhas": total, **detalhes},
        )
        if conn_tls is not None:
            try:
                enviar_json(
                    conn_tls,
                    {
                        "ok": False,
                        "codigo": 429,
                        "erro": "IP_BLOQUEADO",
                        "mensagem": f"IP bloqueado por {IDS_TEMPO_BLOQUEIO}s pelo IDS/IPS.",
                    },
                )
            except OSError:
                pass
    return bloqueou


def tratar_cliente(
    conn_tcp: socket.socket,
    endereco: tuple,
    contexto_tls: ssl.SSLContext,
    usuarios: dict,
    chave_aes: bytes,
    chave_pub_medico,
) -> None:
    """Executa handshake TLS e processa requisicoes autenticadas de um cliente."""
    ip = endereco[0]
    conn_tls: ssl.SSLSocket | None = None
    sessao: dict | None = None

    try:
        conn_tcp.settimeout(TIMEOUT_HANDSHAKE)
        try:
            conn_tls = contexto_tls.wrap_socket(conn_tcp, server_side=True)
            conn_tls.settimeout(TIMEOUT_CONEXAO)
        except (ssl.SSLError, TimeoutError, socket.timeout, OSError) as erro:
            registrar_evento(
                "WARNING",
                "TLS_FALHA",
                ip,
                f"Handshake TLS falhou para {ip}: {erro}",
                detalhes={"erro": str(erro)},
            )
            notificar_falha_e_ids(None, ip, "TLS_FALHA", {"erro": str(erro)})
            return

        cifra = conn_tls.cipher()
        registrar_evento(
            "INFO",
            "CONEXAO_TLS",
            ip,
            f"Conexao TLS estabelecida com {ip} ({conn_tls.version()}, {cifra[0] if cifra else 'desconhecida'})",
            detalhes={"versao_tls": conn_tls.version(), "cifra": cifra[0] if cifra else None},
        )

        buffer = bytearray()
        while True:
            try:
                req = receber_json(conn_tls, buffer)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as erro:
                registrar_evento(
                    "WARNING",
                    "PAYLOAD_MALFORMADO",
                    ip,
                    f"Payload malformado de {ip}: {erro}",
                    usuario=sessao["usuario"] if sessao else None,
                    detalhes={"erro": str(erro)},
                )
                if notificar_falha_e_ids(conn_tls, ip, "PAYLOAD_MALFORMADO", {"erro": str(erro)}):
                    break
                enviar_json(
                    conn_tls,
                    {
                        "ok": False,
                        "codigo": 400,
                        "erro": "PAYLOAD_INVALIDO",
                        "mensagem": "Requisicao malformada.",
                    },
                )
                continue

            if req is None:
                break

            acao = req.get("acao")
            if not isinstance(acao, str):
                registrar_evento(
                    "WARNING",
                    "ACAO_INVALIDA",
                    ip,
                    f"Campo 'acao' ausente ou invalido de {ip}",
                    usuario=sessao["usuario"] if sessao else None,
                )
                if notificar_falha_e_ids(conn_tls, ip, "ACAO_INVALIDA", {}):
                    break
                enviar_json(
                    conn_tls,
                    {
                        "ok": False,
                        "codigo": 400,
                        "erro": "ACAO_INVALIDA",
                        "mensagem": "Informe uma acao valida.",
                    },
                )
                continue

            if acao == "SAIR":
                enviar_json(conn_tls, {"ok": True, "codigo": 200, "mensagem": "Sessao encerrada."})
                break

            if acao == "LOGIN":
                usuario = str(req.get("usuario", "")).strip()
                senha = str(req.get("senha", ""))
                codigo_totp = str(req.get("totp", "")).strip()
                valido, role, motivo = autenticar_usuario(usuarios, usuario, senha, codigo_totp)
                if not valido:
                    registrar_evento(
                        "WARNING",
                        "LOGIN_NEGADO",
                        ip,
                        f"Login negado para '{usuario or '?'}' de {ip} ({motivo})",
                        usuario=usuario or None,
                        detalhes={"motivo": motivo},
                    )
                    if notificar_falha_e_ids(
                        conn_tls, ip, "LOGIN_FALHO", {"usuario": usuario, "motivo": motivo}
                    ):
                        break
                    enviar_json(
                        conn_tls,
                        {
                            "ok": False,
                            "codigo": 401,
                            "erro": "CREDENCIAIS_INVALIDAS",
                            "mensagem": "Usuario, senha ou codigo 2FA invalido.",
                        },
                    )
                    continue

                sessao = {"usuario": usuario, "role": role}
                registrar_evento(
                    "INFO",
                    "LOGIN_ACEITO",
                    ip,
                    f"Login aceito: {usuario} (role={role}) de {ip}",
                    usuario=usuario,
                    detalhes={"role": role},
                )
                enviar_json(
                    conn_tls,
                    {
                        "ok": True,
                        "codigo": 200,
                        "usuario": usuario,
                        "role": role,
                        "mensagem": "Autenticacao PBKDF2 + 2FA TOTP concluida.",
                    },
                )
                continue

            if sessao is None:
                registrar_evento(
                    "WARNING",
                    "NAO_AUTENTICADO",
                    ip,
                    f"Tentativa de '{acao}' sem autenticacao de {ip}",
                    detalhes={"acao": acao},
                )
                if notificar_falha_e_ids(conn_tls, ip, "NAO_AUTENTICADO", {"acao": acao}):
                    break
                enviar_json(
                    conn_tls,
                    {
                        "ok": False,
                        "codigo": 401,
                        "erro": "NAO_AUTENTICADO",
                        "mensagem": "Faca login antes de executar esta acao.",
                    },
                )
                continue

            usuario_atual = sessao["usuario"]
            role_atual = sessao["role"]

            if acao not in {"ENVIAR_LAUDO", "BAIXAR_LAUDO", "LISTAR_STATUS"}:
                registrar_evento(
                    "WARNING",
                    "ACAO_DESCONHECIDA",
                    ip,
                    f"Acao desconhecida '{acao}' enviada por {usuario_atual} ({ip})",
                    usuario=usuario_atual,
                    detalhes={"acao": acao},
                )
                if notificar_falha_e_ids(conn_tls, ip, "ACAO_DESCONHECIDA", {"acao": acao}):
                    break
                enviar_json(
                    conn_tls,
                    {
                        "ok": False,
                        "codigo": 400,
                        "erro": "ACAO_DESCONHECIDA",
                        "mensagem": "Acao nao reconhecida pelo servidor.",
                    },
                )
                continue

            # Verificacao de autorizacao RBAC no servidor (nunca confiar apenas no cliente).
            permitidas = PERMISSOES_RBAC.get(role_atual, set())
            if acao not in permitidas:
                registrar_evento(
                    "WARNING",
                    "RBAC_ACESSO_NEGADO",
                    ip,
                    f"ACESSO NEGADO (403): {usuario_atual} (role={role_atual}) tentou {acao}",
                    usuario=usuario_atual,
                    detalhes={"role": role_atual, "acao": acao},
                )
                enviar_json(
                    conn_tls,
                    {
                        "ok": False,
                        "codigo": 403,
                        "erro": "ACESSO_NEGADO",
                        "mensagem": f"Perfil '{role_atual}' nao tem permissao para {acao}.",
                    },
                )
                continue

            if acao == "ENVIAR_LAUDO":
                paciente = req.get("paciente")
                conteudo = req.get("conteudo")
                assinatura_b64 = req.get("assinatura_b64")
                if (
                    not isinstance(paciente, str)
                    or not paciente.strip()
                    or not isinstance(conteudo, str)
                    or not conteudo.strip()
                    or not isinstance(assinatura_b64, str)
                    or not assinatura_b64.strip()
                ):
                    if notificar_falha_e_ids(conn_tls, ip, "LAUDO_INCOMPLETO", {}):
                        break
                    enviar_json(
                        conn_tls,
                        {
                            "ok": False,
                            "codigo": 400,
                            "erro": "CAMPOS_INVALIDOS",
                            "mensagem": "Informe paciente, conteudo e assinatura_b64.",
                        },
                    )
                    continue

                if not verificar_assinatura_laudo(chave_pub_medico, conteudo, assinatura_b64):
                    registrar_evento(
                        "ALERT",
                        "VIOLACAO_INTEGRIDADE",
                        ip,
                        f"ASSINATURA RSA-PSS INVALIDA/ADULTERADA enviada por {usuario_atual} ({ip}) - laudo rejeitado",
                        usuario=usuario_atual,
                        detalhes={"paciente": paciente.strip()},
                    )
                    enviar_json(
                        conn_tls,
                        {
                            "ok": False,
                            "codigo": 400,
                            "erro": "ASSINATURA_INVALIDA",
                            "mensagem": "Assinatura digital RSA-PSS invalida ou laudo adulterado.",
                        },
                    )
                    continue

                metadados = salvar_laudo_cifrado(
                    chave_aes, usuario_atual, paciente.strip(), conteudo
                )
                registrar_evento(
                    "INFO",
                    "LAUDO_CIFRADO_REPOUSO",
                    ip,
                    f"Assinatura RSA-PSS valida. Laudo {metadados['laudo_id']} cifrado com AES-256-GCM em repouso",
                    usuario=usuario_atual,
                    detalhes={"laudo_id": metadados["laudo_id"], "paciente": metadados["paciente"]},
                )
                enviar_json(
                    conn_tls,
                    {
                        "ok": True,
                        "codigo": 200,
                        "mensagem": "Laudo validado e armazenado cifrado com AES-256-GCM.",
                        "laudo": metadados,
                    },
                )
                continue

            if acao == "LISTAR_STATUS":
                lista = listar_status_laudos()
                registrar_evento(
                    "INFO",
                    "LISTAR_STATUS",
                    ip,
                    f"Status de {len(lista)} laudo(s) consultado por {usuario_atual} ({role_atual})",
                    usuario=usuario_atual,
                    detalhes={"quantidade": len(lista)},
                )
                enviar_json(conn_tls, {"ok": True, "codigo": 200, "laudos": lista})
                continue

            if acao == "BAIXAR_LAUDO":
                laudo_id = str(req.get("laudo_id", "")).strip()
                try:
                    laudo = carregar_laudo_decifrado(chave_aes, laudo_id)
                except ValueError:
                    enviar_json(
                        conn_tls,
                        {
                            "ok": False,
                            "codigo": 400,
                            "erro": "LAUDO_ID_INVALIDO",
                            "mensagem": "Identificador de laudo invalido.",
                        },
                    )
                    continue
                except InvalidTag:
                    registrar_evento(
                        "ALERT",
                        "INTEGRIDADE_REPOUSO_VIOLADA",
                        ip,
                        f"Falha na tag GCM ao decifrar {laudo_id}: possivel adulteracao em disco",
                        usuario=usuario_atual,
                        detalhes={"laudo_id": laudo_id},
                    )
                    enviar_json(
                        conn_tls,
                        {
                            "ok": False,
                            "codigo": 500,
                            "erro": "INTEGRIDADE_REPOUSO_VIOLADA",
                            "mensagem": "Falha ao verificar integridade do arquivo cifrado.",
                        },
                    )
                    continue

                if laudo is None:
                    enviar_json(
                        conn_tls,
                        {
                            "ok": False,
                            "codigo": 404,
                            "erro": "LAUDO_NAO_ENCONTRADO",
                            "mensagem": "Laudo nao encontrado.",
                        },
                    )
                    continue

                registrar_evento(
                    "INFO",
                    "LAUDO_BAIXADO",
                    ip,
                    f"Laudo {laudo_id} decifrado e enviado para {usuario_atual}",
                    usuario=usuario_atual,
                    detalhes={"laudo_id": laudo_id},
                )
                enviar_json(conn_tls, {"ok": True, "codigo": 200, "laudo": laudo})

    except (TimeoutError, socket.timeout):
        registrar_evento(
            "WARNING",
            "TIMEOUT_CONEXAO",
            ip,
            f"Conexao com {ip} encerrada por timeout de inatividade ({TIMEOUT_CONEXAO}s)",
            usuario=sessao["usuario"] if sessao else None,
        )
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError) as erro:
        registrar_evento(
            "WARNING",
            "CONEXAO_INTERROMPIDA",
            ip,
            f"Conexao interrompida com {ip}: {erro}",
            usuario=sessao["usuario"] if sessao else None,
            detalhes={"erro": str(erro)},
        )
    finally:
        for sock in (conn_tls, conn_tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Servidor TLS MedSec para transferencia segura de laudos medicos."
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Endereco IP de escuta (padrao: 0.0.0.0 para aceitar conexoes da VPN).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Porta TCP do servidor TLS (padrao: 8443).",
    )
    args = parser.parse_args()

    try:
        usuarios, chave_aes, chave_pub_medico = carregar_recursos()
        contexto_tls = criar_contexto_tls()
    except (FileNotFoundError, ValueError, ssl.SSLError, OSError) as erro:
        print(f"Erro ao inicializar servidor: {erro}", file=sys.stderr)
        sys.exit(1)

    servidor_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor_tcp.bind((args.host, args.port))
        servidor_tcp.listen(20)
        # Timeout curto no accept() permite responder rapidamente ao Ctrl+C no Windows.
        servidor_tcp.settimeout(1.0)
    except OSError as erro:
        print(f"Erro ao abrir porta {args.host}:{args.port}: {erro}", file=sys.stderr)
        servidor_tcp.close()
        sys.exit(1)

    registrar_evento(
        "INFO",
        "SERVIDOR_INICIADO",
        args.host,
        f"Servidor MedSec TLS ativo em {args.host}:{args.port} (aguardando conexoes; Ctrl+C para encerrar)",
        detalhes={"host": args.host, "port": args.port, "usuarios_carregados": len(usuarios)},
    )

    try:
        while True:
            try:
                conn_tcp, endereco = servidor_tcp.accept()
            except (TimeoutError, socket.timeout):
                continue

            ip_cliente = endereco[0]
            restante = tempo_restante_bloqueio(ip_cliente)
            if restante > 0:
                registrar_evento(
                    "ALERT",
                    "[IDS/IPS ALERT] CONEXAO_RECUSADA_BLACKLIST",
                    ip_cliente,
                    f"Conexao recusada imediatamente: IP {ip_cliente} esta na blacklist ({restante}s restantes)",
                    detalhes={"segundos_restantes": restante},
                )
                conn_tcp.close()
                continue

            if registrar_conexao_ip(ip_cliente):
                registrar_evento(
                    "ALERT",
                    "[IDS/IPS ALERT] IP_BLOQUEADO",
                    ip_cliente,
                    f"IP {ip_cliente} BLOQUEADO por {IDS_TEMPO_BLOQUEIO}s (excesso de conexoes em {IDS_JANELA_SEGUNDOS}s)",
                    detalhes={"motivo": "RATE_LIMIT_CONEXOES", "limite": IDS_MAX_CONEXOES_JANELA},
                )
                conn_tcp.close()
                continue

            thread = threading.Thread(
                target=tratar_cliente,
                args=(
                    conn_tcp,
                    endereco,
                    contexto_tls,
                    usuarios,
                    chave_aes,
                    chave_pub_medico,
                ),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        registrar_evento(
            "INFO",
            "SERVIDOR_ENCERRADO",
            args.host,
            "Servidor encerrado pelo operador.",
        )
    finally:
        servidor_tcp.close()


if __name__ == "__main__":
    main()
