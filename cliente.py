"""Cliente interativo TLS para envio e consulta segura de laudos medicos (RA1 e RA2)."""

import argparse
import base64
from datetime import datetime, timezone
import getpass
import json
from pathlib import Path
import socket
import ssl
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

CA_CERT_PADRAO = Path("certs/ca.crt")
CHAVE_ASSINATURA_PADRAO = Path("certs/medico_sign.key")
DIR_LOGS = Path("logs")
ARQUIVO_LOG = DIR_LOGS / "security_audit.log"

TIMEOUT_REDE = 15.0
MAX_TAMANHO_MSG = 1024 * 1024


def registrar_log(nivel: str, evento: str, detalhes: dict) -> None:
    """Grava evento estruturado do cliente em logs/security_audit.log."""
    try:
        DIR_LOGS.mkdir(parents=True, exist_ok=True)
        registro = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "nivel": nivel,
            "evento": evento,
            "origem": "cliente",
            "detalhes": detalhes,
        }
        with ARQUIVO_LOG.open("a", encoding="utf-8") as arquivo:
            arquivo.write(json.dumps(registro, ensure_ascii=False) + "\n")
    except OSError:
        pass


def criar_contexto_tls_cliente(caminho_ca: Path) -> ssl.SSLContext:
    """Configura contexto TLS exigindo validacao da CA interna e do IP/hostname no SAN."""
    if not caminho_ca.exists():
        raise FileNotFoundError(
            f"Certificado da CA nao encontrado em '{caminho_ca}'. "
            "Copie o arquivo certs/ca.crt gerado pelo servidor."
        )

    contexto = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(caminho_ca)
    )
    # Exige TLS 1.2+ e validacao estrita de cadeia e SAN para impedir ataques Man-in-the-Middle.
    contexto.minimum_version = ssl.TLSVersion.TLSv1_2
    contexto.check_hostname = True
    contexto.verify_mode = ssl.CERT_REQUIRED
    return contexto


def conectar_tls(host: str, port: int, contexto: ssl.SSLContext) -> ssl.SSLSocket:
    """Abre socket TCP e conclui handshake TLS validando o host contra o certificado."""
    sock_tcp = socket.create_connection((host, port), timeout=TIMEOUT_REDE)
    try:
        # server_hostname faz o OpenSSL conferir se o IP/dominio acessado consta no SAN do certificado.
        conn_tls = contexto.wrap_socket(sock_tcp, server_hostname=host)
        conn_tls.settimeout(TIMEOUT_REDE)
        return conn_tls
    except Exception:
        sock_tcp.close()
        raise


def enviar_json(conn: ssl.SSLSocket, payload: dict) -> None:
    """Serializa e envia mensagem JSON terminada por '\n' pelo canal TLS."""
    dados = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    conn.sendall(dados)


def receber_json(conn: ssl.SSLSocket, buffer: bytearray) -> dict:
    """Le uma resposta JSON delimitada por '\n' respeitando limite maximo de tamanho."""
    while b"\n" not in buffer:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionResetError("Servidor encerrou a conexao.")
        buffer.extend(chunk)
        if len(buffer) > MAX_TAMANHO_MSG:
            raise ValueError("Resposta do servidor excede o limite de 1 MB.")

    indice_quebra = buffer.index(b"\n")
    linha = bytes(buffer[:indice_quebra])
    del buffer[: indice_quebra + 1]

    objeto = json.loads(linha.decode("utf-8"))
    if not isinstance(objeto, dict):
        raise ValueError("Resposta do servidor nao e um objeto JSON valido.")
    return objeto


def assinar_laudo(conteudo: str, caminho_chave: Path) -> str:
    """Assina o conteudo do laudo com RSA-PSS + SHA-256 usando a chave privada do medico."""
    if not caminho_chave.exists():
        raise FileNotFoundError(
            f"Chave de assinatura do medico nao encontrada em '{caminho_chave}'."
        )

    chave_privada = serialization.load_pem_private_key(
        caminho_chave.read_bytes(), password=None
    )
    # RSA-PSS com SHA-256 garante autenticidade do autor e deteccao imediata de adulteracao.
    assinatura = chave_privada.sign(
        conteudo.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(assinatura).decode("ascii")


def fluxo_login(conn: ssl.SSLSocket, buffer: bytearray) -> dict | None:
    """Realiza autenticacao com usuario, senha (oculta) e codigo 2FA TOTP."""
    print("\n=== Autenticacao (PBKDF2 + 2FA TOTP) ===")
    while True:
        usuario = input("Usuario (Enter para sair): ").strip()
        if not usuario:
            return None

        # getpass oculta a senha digitada no terminal para proteger contra shoulder surfing na gravacao.
        senha = getpass.getpass("Senha (digitacao oculta, digite e aperte Enter): ")
        totp = input("Codigo 2FA TOTP (6 digitos): ").strip()

        enviar_json(
            conn,
            {
                "acao": "LOGIN",
                "usuario": usuario,
                "senha": senha,
                "totp": totp,
            },
        )
        resposta = receber_json(conn, buffer)

        if resposta.get("ok"):
            role = resposta.get("role", "desconhecido")
            print(f"\nLogin aceito: {usuario} (perfil: {role})")
            registrar_log("INFO", "CLIENTE_LOGIN_OK", {"usuario": usuario, "role": role})
            return {"usuario": usuario, "role": role}

        codigo = resposta.get("codigo")
        erro = resposta.get("erro", "ERRO")
        mensagem = resposta.get("mensagem", "Falha na autenticacao.")
        print(f"\n[ERRO {codigo}] {erro}: {mensagem}\n")
        registrar_log(
            "WARNING",
            "CLIENTE_LOGIN_NEGADO",
            {"usuario": usuario, "codigo": codigo, "erro": erro},
        )
        if codigo == 429:
            return None


def executar_menu(
    conn: ssl.SSLSocket, buffer: bytearray, sessao: dict, caminho_chave: Path
) -> None:
    """Exibe menu interativo para testar envio, listagem de status e download com RBAC."""
    while True:
        print("\n=== Menu MedSec ===")
        print(f"Sessao ativa: {sessao['usuario']} (perfil: {sessao['role']})")
        print("1 - Enviar laudo medico (assinado com RSA-PSS)")
        print("2 - Listar status de laudos")
        print("3 - Baixar laudo medico")
        print("4 - Sair")

        opcao = input("Escolha uma opcao [1-4]: ").strip()

        if opcao == "1":
            paciente = input("Nome do paciente: ").strip()
            conteudo = input("Conteudo do laudo: ").strip()
            if not paciente or not conteudo:
                print("Paciente e conteudo do laudo sao obrigatorios.")
                continue

            try:
                assinatura_b64 = assinar_laudo(conteudo, caminho_chave)
            except FileNotFoundError as erro:
                # Permite demonstrar erro 403 RBAC caso o usuario seja recepcionista sem chave de medico.
                if sessao["role"] != "medico":
                    assinatura_b64 = "SEM_CHAVE"
                else:
                    print(f"[ERRO] {erro}")
                    continue

            enviar_json(
                conn,
                {
                    "acao": "ENVIAR_LAUDO",
                    "paciente": paciente,
                    "conteudo": conteudo,
                    "assinatura_b64": assinatura_b64,
                },
            )
            resp = receber_json(conn, buffer)
            if resp.get("ok"):
                laudo = resp.get("laudo", {})
                print(
                    f"\n[OK] Laudo enviado e cifrado em repouso: {laudo.get('laudo_id')} "
                    f"(algoritmo={laudo.get('algoritmo_repouso')})"
                )
                registrar_log(
                    "INFO",
                    "CLIENTE_LAUDO_ENVIADO",
                    {"laudo_id": laudo.get("laudo_id"), "usuario": sessao["usuario"]},
                )
            else:
                print(
                    f"\n[ERRO {resp.get('codigo')}] {resp.get('erro')}: {resp.get('mensagem')}"
                )
                registrar_log(
                    "WARNING",
                    "CLIENTE_ENVIO_RECUSADO",
                    {"codigo": resp.get("codigo"), "erro": resp.get("erro")},
                )

        elif opcao == "2":
            enviar_json(conn, {"acao": "LISTAR_STATUS"})
            resp = receber_json(conn, buffer)
            if resp.get("ok"):
                laudos = resp.get("laudos", [])
                if not laudos:
                    print("\nNenhum laudo registrado no servidor.")
                else:
                    print(f"\n=== Status dos Laudos ({len(laudos)}) ===")
                    for item in laudos:
                        print(
                            f"- {item.get('laudo_id')} | paciente={item.get('paciente')} "
                            f"| medico={item.get('medico')} | status={item.get('status')} "
                            f"| criado_em={item.get('criado_em')}"
                        )
            else:
                print(
                    f"\n[ERRO {resp.get('codigo')}] {resp.get('erro')}: {resp.get('mensagem')}"
                )

        elif opcao == "3":
            laudo_id = input("ID do laudo (ex: LAUDO-...): ").strip()
            if not laudo_id:
                print("Informe o ID do laudo.")
                continue

            enviar_json(conn, {"acao": "BAIXAR_LAUDO", "laudo_id": laudo_id})
            resp = receber_json(conn, buffer)
            if resp.get("ok"):
                laudo = resp.get("laudo", {})
                print("\n=== Laudo Decifrado ===")
                print(f"ID       : {laudo.get('laudo_id')}")
                print(f"Paciente : {laudo.get('paciente')}")
                print(f"Medico   : {laudo.get('medico')}")
                print(f"Criado em: {laudo.get('criado_em')}")
                print(f"Conteudo : {laudo.get('conteudo')}")
                registrar_log(
                    "INFO",
                    "CLIENTE_LAUDO_BAIXADO",
                    {"laudo_id": laudo_id, "usuario": sessao["usuario"]},
                )
            else:
                print(
                    f"\n[ERRO {resp.get('codigo')}] {resp.get('erro')}: {resp.get('mensagem')}"
                )
                registrar_log(
                    "WARNING",
                    "CLIENTE_DOWNLOAD_RECUSADO",
                    {"laudo_id": laudo_id, "codigo": resp.get("codigo"), "erro": resp.get("erro")},
                )

        elif opcao == "4":
            enviar_json(conn, {"acao": "SAIR"})
            resp = receber_json(conn, buffer)
            print(resp.get("mensagem", "Conexao encerrada."))
            break

        else:
            print("Opcao invalida. Escolha de 1 a 4.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cliente TLS MedSec para envio e consulta de laudos medicos."
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
    args = parser.parse_args()

    caminho_ca = Path(args.ca)
    caminho_chave = Path(args.key)
    conn_tls: ssl.SSLSocket | None = None

    try:
        contexto_tls = criar_contexto_tls_cliente(caminho_ca)
        conn_tls = conectar_tls(args.host, args.port, contexto_tls)
        cifra = conn_tls.cipher()
        print(
            f"Conectado com seguranca a {args.host}:{args.port} "
            f"({conn_tls.version()}, {cifra[0] if cifra else 'desconhecida'}, "
            f"certificado validado por {caminho_ca})"
        )
        registrar_log(
            "INFO",
            "CLIENTE_CONEXAO_TLS",
            {"host": args.host, "port": args.port, "versao_tls": conn_tls.version()},
        )

        buffer = bytearray()
        sessao = fluxo_login(conn_tls, buffer)
        if sessao is not None:
            executar_menu(conn_tls, buffer, sessao, caminho_chave)

    except FileNotFoundError as erro:
        print(f"Arquivo ausente: {erro}", file=sys.stderr)
        sys.exit(1)
    except ssl.SSLCertVerificationError as erro:
        registrar_log("ALERT", "CLIENTE_TLS_CERT_INVALIDO", {"host": args.host, "erro": str(erro)})
        print(
            f"Falha na validacao do certificado TLS do servidor: {erro}\n"
            "Verifique se certs/ca.crt e o correto e se o IP do servidor esta no SAN do certificado.",
            file=sys.stderr,
        )
        sys.exit(1)
    except ssl.SSLError as erro:
        registrar_log("ERROR", "CLIENTE_TLS_ERRO", {"host": args.host, "erro": str(erro)})
        print(
            f"Erro TLS ao conectar em {args.host}:{args.port}: {erro}",
            file=sys.stderr,
        )
        sys.exit(1)
    except ConnectionRefusedError:
        print(
            f"Conexao recusada por {args.host}:{args.port}. "
            "Verifique se servidor.py esta rodando e se o firewall permite a porta.",
            file=sys.stderr,
        )
        sys.exit(1)
    except (TimeoutError, socket.timeout):
        print(
            f"Timeout de rede ou inatividade ({TIMEOUT_REDE:.0f}s) ao comunicar com {args.host}:{args.port}.",
            file=sys.stderr,
        )
        sys.exit(1)
    except (ConnectionResetError, BrokenPipeError) as erro:
        print(
            f"Conexao encerrada pelo servidor ({erro}). "
            "Possivel timeout de inatividade (120s) ou bloqueio pelo IDS/IPS.",
            file=sys.stderr,
        )
        sys.exit(1)
    except (json.JSONDecodeError, ValueError) as erro:
        print(f"Erro nos dados recebidos do servidor: {erro}", file=sys.stderr)
        sys.exit(1)
    except OSError as erro:
        print(f"Erro de rede ou arquivo: {erro}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nCliente encerrado pelo usuario.")
    finally:
        if conn_tls is not None:
            try:
                conn_tls.close()
            except OSError:
                pass


if __name__ == "__main__":
    main()
