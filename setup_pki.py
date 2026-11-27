"""Provisionamento inicial de PKI, chaves criptograficas e usuarios do sistema MedSec."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pyotp

DIR_CERTS = Path("certs")
DIR_DADOS = Path("dados")
DIR_LAUDOS = DIR_DADOS / "laudos"
DIR_LOGS = Path("logs")
ARQUIVO_LOG = DIR_LOGS / "security_audit.log"

# 600.000 iteracoes de PBKDF2-SHA256 dificultam quebra offline por forca bruta (recomendacao OWASP).
PBKDF2_ITERACOES = 600_000


def registrar_log(evento: str, status: str, detalhes: dict) -> None:
    """Grava evento estruturado em JSON Lines no log de auditoria."""
    DIR_LOGS.mkdir(parents=True, exist_ok=True)
    registro = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nivel": "ERROR" if status == "ERRO" else "INFO",
        "evento": evento,
        "status": status,
        "detalhes": detalhes,
    }
    with ARQUIVO_LOG.open("a", encoding="utf-8") as arquivo:
        arquivo.write(json.dumps(registro, ensure_ascii=False) + "\n")


def obter_ips_servidor(
    ips_cli: list[str] | None,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Coleta e valida os IPs que serao incluidos no SAN do certificado TLS do servidor."""
    # Sempre inclui loopback para permitir testes locais antes de rodar via VPN.
    brutos: list[str] = ["127.0.0.1"]

    if ips_cli is not None:
        brutos.extend(ips_cli)
    else:
        entrada = input(
            "Digite o IP do servidor na VPN (ex: 25.10.20.30, separe multiplos por virgula ou Enter para apenas 127.0.0.1): "
        ).strip()
        if entrada:
            brutos.extend(item.strip() for item in entrada.split(",") if item.strip())

    ips_validados: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    vistos: set[str] = set()
    for item in brutos:
        ip_obj = ipaddress.ip_address(item)
        texto_ip = str(ip_obj)
        if texto_ip not in vistos:
            vistos.add(texto_ip)
            ips_validados.append(ip_obj)

    return ips_validados


def gerar_chave_rsa() -> rsa.RSAPrivateKey:
    """Gera par RSA de 2048 bits, padrao seguro para certificados X.509 e assinatura digital."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def salvar_chave_privada(chave: rsa.RSAPrivateKey, caminho: Path) -> None:
    # Em ambiente academico salvamos sem senha para automacao; em producao ficaria em HSM/KMS ou protegida por passphrase.
    pem = chave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    caminho.write_bytes(pem)


def salvar_chave_publica(chave_pub: rsa.RSAPublicKey, caminho: Path) -> None:
    pem = chave_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    caminho.write_bytes(pem)


def salvar_certificado(cert: x509.Certificate, caminho: Path) -> None:
    caminho.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def gerar_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Cria a Autoridade Certificadora (CA) interna da clinica para assinar o certificado do servidor."""
    chave_ca = gerar_chave_rsa()
    identidade = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "PR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Curitiba"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Clinica MedSec"),
        x509.NameAttribute(NameOID.COMMON_NAME, "MedSec Root CA"),
    ])

    agora = datetime.now(timezone.utc)
    # Margem de 5 minutos no inicio evita rejeicao por pequena dessincronia de relogio entre os dois PCs.
    cert_ca = (
        x509.CertificateBuilder()
        .subject_name(identidade)
        .issuer_name(identidade)
        .public_key(chave_ca.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora - timedelta(minutes=5))
        .not_valid_after(agora + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(chave_ca.public_key()),
            critical=False,
        )
        .sign(private_key=chave_ca, algorithm=hashes.SHA256())
    )

    salvar_chave_privada(chave_ca, DIR_CERTS / "ca.key")
    salvar_certificado(cert_ca, DIR_CERTS / "ca.crt")
    return chave_ca, cert_ca


def gerar_certificado_servidor(
    chave_ca: rsa.RSAPrivateKey,
    cert_ca: x509.Certificate,
    ips_san: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> None:
    """Emite o certificado TLS do servidor com os IPs reais no SubjectAlternativeName (SAN)."""
    chave_srv = gerar_chave_rsa()
    sujeito = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "PR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Curitiba"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Clinica MedSec"),
        x509.NameAttribute(NameOID.COMMON_NAME, "servidor.medsec.local"),
    ])

    # Clientes TLS modernos validam o IP ou hostname no SAN, nao apenas no Common Name (CN).
    entradas_san: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.DNSName("servidor.medsec.local"),
    ]
    entradas_san.extend(x509.IPAddress(ip) for ip in ips_san)

    agora = datetime.now(timezone.utc)
    cert_srv = (
        x509.CertificateBuilder()
        .subject_name(sujeito)
        .issuer_name(cert_ca.subject)
        .public_key(chave_srv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora - timedelta(minutes=5))
        .not_valid_after(agora + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(entradas_san), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(chave_srv.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(chave_ca.public_key()),
            critical=False,
        )
        .sign(private_key=chave_ca, algorithm=hashes.SHA256())
    )

    salvar_chave_privada(chave_srv, DIR_CERTS / "servidor.key")
    salvar_certificado(cert_srv, DIR_CERTS / "servidor.crt")


def gerar_chaves_assinatura_medico() -> None:
    """Gera par RSA dedicado para assinatura RSA-PSS dos laudos, separado da chave TLS do servidor."""
    # Separar chaves por finalidade reduz impacto caso uma chave seja comprometida e garante nao-repudio.
    chave_medico = gerar_chave_rsa()
    salvar_chave_privada(chave_medico, DIR_CERTS / "medico_sign.key")
    salvar_chave_publica(chave_medico.public_key(), DIR_CERTS / "medico_sign.pub")


def gerar_chave_aes_repouso() -> None:
    """Gera chave simetrica aleatoria de 256 bits para cifragem dos laudos em repouso (AES-256-GCM)."""
    chave_aes = secrets.token_bytes(32)
    (DIR_DADOS / "aes_repouso.key").write_bytes(chave_aes)


def hash_senha_pbkdf2(senha: str) -> tuple[str, str]:
    """Deriva hash PBKDF2-HMAC-SHA256 com salt aleatorio de 128 bits por usuario."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt, PBKDF2_ITERACOES)
    return salt.hex(), digest.hex()


def gerar_usuarios_iniciais() -> list[dict]:
    """Cria base inicial de usuarios com RBAC (medico e recepcionista) e segredo 2FA TOTP."""
    contas_base = [
        ("dr_silva", "Medico@2026", "medico"),
        ("recep_ana", "Recep@2026", "recepcionista"),
    ]
    banco_usuarios: dict[str, dict] = {}
    resumo: list[dict] = []

    for usuario, senha, role in contas_base:
        salt_hex, hash_hex = hash_senha_pbkdf2(senha)
        totp_secret = pyotp.random_base32()
        banco_usuarios[usuario] = {
            "role": role,
            "salt": salt_hex,
            "password_hash": hash_hex,
            "iterations": PBKDF2_ITERACOES,
            "totp_secret": totp_secret,
        }
        uri_totp = pyotp.TOTP(totp_secret).provisioning_uri(
            name=usuario,
            issuer_name="MedSec",
        )
        resumo.append({
            "usuario": usuario,
            "senha": senha,
            "role": role,
            "totp_secret": totp_secret,
            "uri_totp": uri_totp,
        })

    # Nunca gravamos senha em texto claro; apenas salt, hash PBKDF2 e segredo TOTP.
    (DIR_DADOS / "usuarios.json").write_text(
        json.dumps(banco_usuarios, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return resumo


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Gera PKI, chaves criptograficas e usuarios iniciais do projeto MedSec."
    )
    parser.add_argument(
        "--ip",
        nargs="*",
        default=None,
        help="IP(s) do servidor na VPN para incluir no certificado TLS (alem de 127.0.0.1).",
    )
    args = parser.parse_args()

    try:
        DIR_CERTS.mkdir(parents=True, exist_ok=True)
        DIR_DADOS.mkdir(parents=True, exist_ok=True)
        DIR_LAUDOS.mkdir(parents=True, exist_ok=True)
        DIR_LOGS.mkdir(parents=True, exist_ok=True)

        ips_san = obter_ips_servidor(args.ip)
        chave_ca, cert_ca = gerar_ca()
        gerar_certificado_servidor(chave_ca, cert_ca, ips_san)
        gerar_chaves_assinatura_medico()
        gerar_chave_aes_repouso()
        resumo_usuarios = gerar_usuarios_iniciais()

        lista_ips = [str(ip) for ip in ips_san]
        registrar_log(
            "PKI_SETUP",
            "OK",
            {
                "ips_san": lista_ips,
                "usuarios": [u["usuario"] for u in resumo_usuarios],
            },
        )

        print("\n=== Setup PKI e Chaves Concluido ===")
        print(f"IPs no SAN do certificado TLS: {', '.join(lista_ips)}")
        print("Arquivos gerados em certs/, dados/ e logs/security_audit.log\n")

        print("=== Usuarios Criados (anote os segredos TOTP) ===")
        for item in resumo_usuarios:
            print(
                f"- {item['usuario']} | role: {item['role']} | senha: {item['senha']} | TOTP secret: {item['totp_secret']}"
            )
            print(f"  URI TOTP: {item['uri_totp']}")

        print("\n=== Arquivos para copiar para o PC Cliente (colega) ===")
        print("1. certs/ca.crt         (para validar o certificado TLS do servidor)")
        print("2. certs/medico_sign.key (para assinar laudos enviados pelo medico)")
        print("NAO copie ca.key, servidor.key, dados/aes_repouso.key nem dados/usuarios.json.")

    except ValueError as erro:
        registrar_log("PKI_SETUP", "ERRO", {"motivo": f"IP invalido: {erro}"})
        print(f"Erro de validacao: {erro}", file=sys.stderr)
        sys.exit(1)
    except OSError as erro:
        registrar_log("PKI_SETUP", "ERRO", {"motivo": f"Falha de arquivo/diretorio: {erro}"})
        print(f"Erro ao gravar arquivos: {erro}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        registrar_log("PKI_SETUP", "ERRO", {"motivo": "Operacao cancelada pelo usuario"})
        print("\nOperacao cancelada pelo usuario.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
