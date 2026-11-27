"""Suite de testes de seguranca e ataque (T01 a T04) para validacao de RA1, RA2 e RA3."""

import argparse
import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import ssl
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

CA_CERT_PADRAO = Path("certs/ca.crt")
CHAVE_ASSINATURA_PADRAO = Path("certs/medico_sign.key")
ARQUIVO_USUARIOS_LOCAL = Path("dados/usuarios.json")
DIR_LOGS = Path("logs")
ARQUIVO_LOG = DIR_LOGS / "security_audit.log"

TIMEOUT_REDE = 15.0
MAX_TAMANHO_MSG = 1024 * 1024

USUARIO_MEDICO = "dr_silva"
SENHA_MEDICO = "Medico@2026"
USUARIO_RECEP = "recep_ana"
SENHA_RECEP = "Recep@2026"


def registrar_log(nivel: str, evento: str, detalhes: dict) -> None:
    """Grava resultado estruturado dos testes em logs/security_audit.log."""
    try:
        DIR_LOGS.mkdir(parents=True, exist_ok=True)
        registro = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nivel": nivel,
            "evento": evento,
            "origem": "testes_ataque",
            "detalhes": detalhes,
        }
        with ARQUIVO_LOG.open("a", encoding="utf-8") as arquivo:
            arquivo.write(json.dumps(registro, ensure_ascii=False) + "\n")
    except OSError:
        pass


def criar_contexto_tls(caminho_ca: Path) -> ssl.SSLContext:
    """Configura TLS 1.2+ validando o certificado do servidor contra a CA interna."""
    if not caminho_ca.exists():
        raise FileNotFoundError(
            f"Certificado da CA nao encontrado em '{caminho_ca}'."
        )
    contexto = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(caminho_ca)
    )
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.check_hostname = True
    contexto.verify_mode = ssl.CERT_REQUIRED
    return contexto


def conectar_tls(host: str, port: int, contexto: ssl.SSLContext) -> ssl.SSLSocket:
    """Estabelece conexao TCP+TLS com validacao de SAN/IP."""
    sock_tcp = socket.create_connection((host, port), timeout=TIMEOUT_REDE)
    try:
        conn_tls = contexto.wrap_socket(sock_tcp, server_hostname=host)
        conn_tls.settimeout(TIMEOUT_REDE)
        return conn_tls
    except Exception:
        sock_tcp.close()
        raise


def enviar_json(conn: ssl.SSLSocket, payload: dict) -> None:
    """Envia mensagem JSON terminada por '\n' pelo canal TLS."""
    dados = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    conn.sendall(dados)


def receber_json(conn: ssl.SSLSocket, buffer: bytearray) -> dict:
    """Le uma resposta JSON delimitada por '\n' respeitando limite maximo."""
    while b"\n" not in buffer:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionResetError("Servidor encerrou a conexao.")
        buffer.extend(chunk)
        if len(buffer) > MAX_TAMANHO_MSG:
            raise ValueError("Resposta excede o limite de 1 MB.")

    indice_quebra = buffer.index(b"\n")
    linha = bytes(buffer[:indice_quebra])
    del buffer[: indice_quebra + 1]

    objeto = json.loads(linha.decode("utf-8"))
    if not isinstance(objeto, dict):
        raise ValueError("Resposta recebida nao e um objeto JSON.")
    return objeto


def assinar_laudo(conteudo: str, caminho_chave: Path) -> str:
    """Assina texto com RSA-PSS + SHA-256 usando a chave privada do medico."""
    if not caminho_chave.exists():
        raise FileNotFoundError(
            f"Chave de assinatura nao encontrada em '{caminho_chave}'."
        )
    chave_privada = serialization.load_pem_private_key(
        caminho_chave.read_bytes(), password=None
    )
    assinatura = chave_privada.sign(
        conteudo.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(assinatura).decode("ascii")


def obter_totp_secret(usuario: str, valor_cli: str | None) -> str:
    """Obtem segredo TOTP via CLI, dados/usuarios.json local ou prompt interativo."""
    if valor_cli and valor_cli.strip():
        return valor_cli.strip()

    if ARQUIVO_USUARIOS_LOCAL.exists():
        try:
            usuarios = json.loads(ARQUIVO_USUARIOS_LOCAL.read_text(encoding="utf-8"))
            secret = usuarios.get(usuario, {}).get("totp_secret", "").strip()
            if secret:
                return secret
        except (OSError, json.JSONDecodeError):
            pass

    # No PC remoto do colega nao existe usuarios.json; pedimos o segredo anotado no setup.
    secret_digitado = input(f"Informe o TOTP secret Base32 de '{usuario}': ").strip()
    if not secret_digitado:
        raise ValueError(f"TOTP secret de '{usuario}' nao informado.")
    return secret_digitado


def fazer_login(
    conn: ssl.SSLSocket, buffer: bytearray, usuario: str, senha: str, totp_secret: str
) -> dict:
    """Gera token TOTP valido e executa LOGIN no servidor."""
    codigo_totp = pyotp.TOTP(totp_secret).now()
    enviar_json(
        conn,
        {
            "acao": "LOGIN",
            "usuario": usuario,
            "senha": senha,
            "totp": codigo_totp,
        },
    )
    return receber_json(conn, buffer)


def fechar_seguro(conn: ssl.SSLSocket | None) -> None:
    if conn is not None:
        try:
            conn.close()
        except OSError:
            pass


def teste_t01_rbac(
    host: str, port: int, contexto: ssl.SSLContext, totp_recep: str
) -> bool:
    """T01 (RA1): recep_ana consulta status (200), mas recebe 403 ao enviar/baixar laudos."""
    print("\n--- T01: Controle de Acesso RBAC (recep_ana) ---")
    conn: ssl.SSLSocket | None = None
    try:
        conn = conectar_tls(host, port, contexto)
        buffer = bytearray()

        resp_login = fazer_login(conn, buffer, USUARIO_RECEP, SENHA_RECEP, totp_recep)
        if not resp_login.get("ok"):
            print(f"[FALHOU] Login de {USUARIO_RECEP} recusado: {resp_login}")
            return False
        print(f"[OK] Login aceito: {USUARIO_RECEP} (role={resp_login.get('role')})")

        enviar_json(conn, {"acao": "LISTAR_STATUS"})
        resp_status = receber_json(conn, buffer)
        status_ok = bool(resp_status.get("ok") and resp_status.get("codigo") == 200)
        print(f"[{'OK' if status_ok else 'FALHOU'}] LISTAR_STATUS -> codigo={resp_status.get('codigo')}")

        # Recepcionista tenta enviar laudo sem autorizacao no RBAC.
        enviar_json(
            conn,
            {
                "acao": "ENVIAR_LAUDO",
                "paciente": "Paciente Teste RBAC",
                "conteudo": "Tentativa nao autorizada.",
                "assinatura_b64": "NAO_APLICAVEL",
            },
        )
        resp_envio = receber_json(conn, buffer)
        envio_negado = (
            resp_envio.get("codigo") == 403 and resp_envio.get("erro") == "ACESSO_NEGADO"
        )
        print(
            f"[{'OK' if envio_negado else 'FALHOU'}] ENVIAR_LAUDO bloqueado -> "
            f"codigo={resp_envio.get('codigo')} erro={resp_envio.get('erro')}"
        )

        # Recepcionista tenta baixar laudo sem autorizacao no RBAC.
        enviar_json(conn, {"acao": "BAIXAR_LAUDO", "laudo_id": "LAUDO-TESTE-RBAC"})
        resp_download = receber_json(conn, buffer)
        download_negado = (
            resp_download.get("codigo") == 403
            and resp_download.get("erro") == "ACESSO_NEGADO"
        )
        print(
            f"[{'OK' if download_negado else 'FALHOU'}] BAIXAR_LAUDO bloqueado -> "
            f"codigo={resp_download.get('codigo')} erro={resp_download.get('erro')}"
        )

        enviar_json(conn, {"acao": "SAIR"})
        receber_json(conn, buffer)

        passou = status_ok and envio_negado and download_negado
        registrar_log(
            "INFO" if passou else "ERROR",
            "TESTE_T01_RBAC",
            {"passou": passou},
        )
        return passou
    finally:
        fechar_seguro(conn)


def teste_t02_envio_legitimo(
    host: str,
    port: int,
    contexto: ssl.SSLContext,
    caminho_chave: Path,
    totp_medico: str,
) -> bool:
    """T02 (RA2/Wireshark): dr_silva envia laudo assinado em TLS e baixa decifrado integro."""
    print("\n--- T02: Envio Legitimo TLS + RSA-PSS + AES-256-GCM (dr_silva) ---")
    conn: ssl.SSLSocket | None = None
    conteudo_original = (
        "Laudo T02: Radiografia de torax sem alteracoes agudas. Conduta: alta ambulatorial."
    )
    try:
        conn = conectar_tls(host, port, contexto)
        cifra = conn.cipher()
        print(
            f"[OK] Canal TLS ativo: {conn.version()} ({cifra[0] if cifra else 'desconhecida'})"
        )
        buffer = bytearray()

        resp_login = fazer_login(conn, buffer, USUARIO_MEDICO, SENHA_MEDICO, totp_medico)
        if not resp_login.get("ok"):
            print(f"[FALHOU] Login de {USUARIO_MEDICO} recusado: {resp_login}")
            return False
        print(f"[OK] Login aceito: {USUARIO_MEDICO} (role={resp_login.get('role')})")

        assinatura_b64 = assinar_laudo(conteudo_original, caminho_chave)
        enviar_json(
            conn,
            {
                "acao": "ENVIAR_LAUDO",
                "paciente": "Carlos Eduardo T02",
                "conteudo": conteudo_original,
                "assinatura_b64": assinatura_b64,
            },
        )
        resp_envio = receber_json(conn, buffer)
        if not resp_envio.get("ok"):
            print(f"[FALHOU] Envio legitimo rejeitado: {resp_envio}")
            return False

        laudo_id = resp_envio["laudo"]["laudo_id"]
        print(
            f"[OK] Laudo armazenado cifrado em repouso: {laudo_id} "
            f"(algoritmo={resp_envio['laudo'].get('algoritmo_repouso')})"
        )

        # Baixa o mesmo laudo para comprovar decifragem AES-256-GCM sem perda de integridade.
        enviar_json(conn, {"acao": "BAIXAR_LAUDO", "laudo_id": laudo_id})
        resp_download = receber_json(conn, buffer)
        conteudo_retornado = resp_download.get("laudo", {}).get("conteudo")
        integro = bool(resp_download.get("ok") and conteudo_retornado == conteudo_original)
        print(
            f"[{'OK' if integro else 'FALHOU'}] Download e decifragem conferem exatamente com o texto original."
        )

        enviar_json(conn, {"acao": "SAIR"})
        receber_json(conn, buffer)

        registrar_log(
            "INFO" if integro else "ERROR",
            "TESTE_T02_ENVIO_LEGITIMO",
            {"passou": integro, "laudo_id": laudo_id},
        )
        return integro
    finally:
        fechar_seguro(conn)


def teste_t03_adulteracao_laudo(
    host: str,
    port: int,
    contexto: ssl.SSLContext,
    caminho_chave: Path,
    totp_medico: str,
) -> bool:
    """T03 (RA2): adultera texto apos assinatura RSA-PSS e valida rejeicao pelo servidor."""
    print("\n--- T03: Adulteracao de Laudo / Assinatura Invalida ---")
    conn: ssl.SSLSocket | None = None
    conteudo_assinado = "Resultado do exame: NEGATIVO para fratura."
    # Simula atacante ou falha alterando o conteudo em transito sem ter a chave para reassinar.
    conteudo_adulterado = "Resultado do exame: POSITIVO para fratura (ADULTERADO)."
    try:
        conn = conectar_tls(host, port, contexto)
        buffer = bytearray()

        resp_login = fazer_login(conn, buffer, USUARIO_MEDICO, SENHA_MEDICO, totp_medico)
        if not resp_login.get("ok"):
            print(f"[FALHOU] Login de {USUARIO_MEDICO} recusado: {resp_login}")
            return False

        assinatura_valida_original = assinar_laudo(conteudo_assinado, caminho_chave)
        enviar_json(
            conn,
            {
                "acao": "ENVIAR_LAUDO",
                "paciente": "Paciente Teste T03",
                "conteudo": conteudo_adulterado,
                "assinatura_b64": assinatura_valida_original,
            },
        )
        resp = receber_json(conn, buffer)
        rejeitado = (
            not resp.get("ok")
            and resp.get("codigo") == 400
            and resp.get("erro") == "ASSINATURA_INVALIDA"
        )
        print(
            f"[{'OK' if rejeitado else 'FALHOU'}] Laudo adulterado rejeitado -> "
            f"codigo={resp.get('codigo')} erro={resp.get('erro')}"
        )

        enviar_json(conn, {"acao": "SAIR"})
        receber_json(conn, buffer)

        registrar_log(
            "INFO" if rejeitado else "ERROR",
            "TESTE_T03_ADULTERACAO",
            {"passou": rejeitado, "codigo": resp.get("codigo"), "erro": resp.get("erro")},
        )
        return rejeitado
    finally:
        fechar_seguro(conn)


def teste_t04_forca_bruta_ids(
    host: str, port: int, contexto: ssl.SSLContext
) -> bool:
    """T04 (RA3): dispara tentativas de login invalidas e valida bloqueio do IP pelo IDS/IPS."""
    print("\n--- T04: Forca Bruta e Bloqueio Automatico IDS/IPS ---")
    conn: ssl.SSLSocket | None = None
    bloqueou_429 = False

    try:
        conn = conectar_tls(host, port, contexto)
        buffer = bytearray()

        for tentativa in range(1, 6):
            try:
                enviar_json(
                    conn,
                    {
                        "acao": "LOGIN",
                        "usuario": USUARIO_MEDICO,
                        "senha": f"SenhaErrada#{tentativa}",
                        "totp": "000000",
                    },
                )
                resp = receber_json(conn, buffer)
                codigo = resp.get("codigo")
                erro = resp.get("erro")
                print(f"Tentativa {tentativa}: codigo={codigo} erro={erro}")
                if codigo == 429 and erro == "IP_BLOQUEADO":
                    bloqueou_429 = True
                    break
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, ssl.SSLError):
                # O servidor fecha a conexao imediatamente ao atingir o limiar de bloqueio.
                if tentativa >= 4:
                    bloqueou_429 = True
                break
    finally:
        fechar_seguro(conn)

    if not bloqueou_429:
        print("[FALHOU] IDS/IPS nao retornou bloqueio (429 IP_BLOQUEADO).")
        registrar_log("ERROR", "TESTE_T04_IDS", {"passou": False, "motivo": "sem_429"})
        return False

    # Pequena pausa para garantir que a blacklist esteja ativa e testar nova conexao.
    time.sleep(0.5)
    conexao_recusada_blacklist = False
    conn_pos_bloqueio: ssl.SSLSocket | None = None
    try:
        conn_pos_bloqueio = conectar_tls(host, port, contexto)
        # Se o TCP aceitou antes do fechamento, tenta ler para confirmar recusa imediata do socket.
        enviar_json(conn_pos_bloqueio, {"acao": "LISTAR_STATUS"})
        receber_json(conn_pos_bloqueio, bytearray())
        print("[FALHOU] Nova conexao apos bloqueio nao foi recusada pela blacklist.")
    except (
        ssl.SSLError,
        ConnectionResetError,
        ConnectionAbortedError,
        BrokenPipeError,
        TimeoutError,
        OSError,
    ) as erro:
        conexao_recusada_blacklist = True
        print(f"[OK] Nova conexao recusada imediatamente pela blacklist ({erro}).")
    finally:
        fechar_seguro(conn_pos_bloqueio)

    passou = bloqueou_429 and conexao_recusada_blacklist
    registrar_log(
        "INFO" if passou else "ERROR",
        "TESTE_T04_IDS",
        {"passou": passou, "bloqueou_429": bloqueou_429, "recusou_nova_conexao": conexao_recusada_blacklist},
    )
    return passou


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa os 4 casos de teste de seguranca (T01 a T04) contra o servidor MedSec."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="IP do servidor na VPN ou 127.0.0.1 para teste local (padrao: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="Porta TCP TLS do servidor (padrao: 8443).",
    )
    parser.add_argument(
        "--ca",
        default=str(CA_CERT_PADRAO),
        help="Caminho do certificado da CA (padrao: certs/ca.crt).",
    )
    parser.add_argument(
        "--key",
        default=str(CHAVE_ASSINATURA_PADRAO),
        help="Caminho da chave privada RSA do medico (padrao: certs/medico_sign.key).",
    )
    parser.add_argument(
        "--totp-medico",
        default=None,
        help="TOTP secret Base32 de dr_silva (opcional se dados/usuarios.json existir).",
    )
    parser.add_argument(
        "--totp-recep",
        default=None,
        help="TOTP secret Base32 de recep_ana (opcional se dados/usuarios.json existir).",
    )
    parser.add_argument(
        "--teste",
        choices=["TODOS", "T01", "T02", "T03", "T04"],
        default="TODOS",
        help="Executa todos os testes ou apenas um especifico (padrao: TODOS).",
    )
    args = parser.parse_args()

    caminho_ca = Path(args.ca)
    caminho_chave = Path(args.key)

    try:
        contexto_tls = criar_contexto_tls(caminho_ca)
        selecionados = (
            ["T01", "T02", "T03", "T04"] if args.teste == "TODOS" else [args.teste]
        )

        totp_recep = (
            obter_totp_secret(USUARIO_RECEP, args.totp_recep)
            if "T01" in selecionados
            else ""
        )
        totp_medico = (
            obter_totp_secret(USUARIO_MEDICO, args.totp_medico)
            if any(t in selecionados for t in ("T02", "T03"))
            else ""
        )

        resultados: dict[str, bool] = {}
        for codigo_teste in selecionados:
            try:
                if codigo_teste == "T01":
                    resultados["T01"] = teste_t01_rbac(
                        args.host, args.port, contexto_tls, totp_recep
                    )
                elif codigo_teste == "T02":
                    resultados["T02"] = teste_t02_envio_legitimo(
                        args.host, args.port, contexto_tls, caminho_chave, totp_medico
                    )
                elif codigo_teste == "T03":
                    resultados["T03"] = teste_t03_adulteracao_laudo(
                        args.host, args.port, contexto_tls, caminho_chave, totp_medico
                    )
                elif codigo_teste == "T04":
                    resultados["T04"] = teste_t04_forca_bruta_ids(
                        args.host, args.port, contexto_tls
                    )
            except FileNotFoundError as erro:
                print(f"[ERRO] {codigo_teste}: {erro}", file=sys.stderr)
                resultados[codigo_teste] = False
            except ssl.SSLCertVerificationError as erro:
                print(
                    f"[ERRO] {codigo_teste}: certificado TLS invalido para {args.host}: {erro}",
                    file=sys.stderr,
                )
                resultados[codigo_teste] = False
            except ConnectionRefusedError:
                print(
                    f"[ERRO] {codigo_teste}: conexao recusada por {args.host}:{args.port}.",
                    file=sys.stderr,
                )
                resultados[codigo_teste] = False
            except (
                ssl.SSLError,
                ConnectionResetError,
                ConnectionAbortedError,
                BrokenPipeError,
                TimeoutError,
                socket.timeout,
                json.JSONDecodeError,
                ValueError,
                OSError,
            ) as erro:
                print(
                    f"[ERRO] {codigo_teste}: {erro} "
                    "(se voce rodou o T04 ha menos de 120s, este IP pode estar na blacklist do servidor).",
                    file=sys.stderr,
                )
                resultados[codigo_teste] = False

        print("\n=== Resumo dos Testes ===")
        todos_ok = True
        for codigo_teste, passou in resultados.items():
            print(f"- {codigo_teste}: {'PASSOU' if passou else 'FALHOU'}")
            if not passou:
                todos_ok = False

        sys.exit(0 if todos_ok else 1)

    except (FileNotFoundError, ValueError) as erro:
        print(f"Erro de configuracao: {erro}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nExecucao interrompida pelo usuario.")
        sys.exit(1)


if __name__ == "__main__":
    main()
