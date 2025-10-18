#!/usr/bin/env python3
"""
CLI de administración de OpenVPN.

Funciones principales:
- add: crear cliente permanente (certificado largo) y generar .ovpn
- add-temp: crear cliente temporal (caduca en X días) y generar .ovpn
- revoke: revocar/bloquear cliente y actualizar CRL
- list: listar clientes (válidos/revocados) desde el índice de la PKI
- connected: listar clientes conectados desde openvpn-status.log (status-version 2)
- setup-status: asegurar directivas de estado en server.conf y recargar servicio

Requisitos:
- Ejecutar con privilegios de superusuario (root)
- Entorno con OpenVPN y easy-rsa instalados por openvpn-install
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


# Rutas clave del despliegue por defecto del script openvpn-install
SERVER_CONF = Path("/etc/openvpn/server/server.conf")
EASYRSA_DIR = Path("/etc/openvpn/server/easy-rsa")
PKI_DIR = EASYRSA_DIR / "pki"
CLIENT_INLINE_DIR = PKI_DIR / "inline" / "private"
CLIENT_TEMPLATE = Path("/etc/openvpn/server/client-common.txt")
STATUS_LOG = Path("/etc/openvpn/server/openvpn-status.log")
CRL_SOURCE = PKI_DIR / "crl.pem"
CRL_TARGET = Path("/etc/openvpn/server/crl.pem")


class CliError(Exception):
    pass


def require_root() -> None:
    try:
        if os.geteuid() != 0:
            raise CliError("Este CLI debe ejecutarse como root (sudo).")
    except AttributeError:
        # os.geteuid no está disponible en algunos sistemas (p.ej., Windows)
        # Asumimos que se ejecuta en Linux del servidor OpenVPN.
        pass


def run_cmd(cmd: List[str], cwd: Optional[Path] = None) -> str:
    try:
        result = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise CliError(
            f"Error al ejecutar: {' '.join(cmd)}\nSTDOUT: {exc.stdout}\nSTDERR: {exc.stderr}"
        ) from exc


def detect_group_name() -> str:
    """Devuelve el grupo para 'nobody:<group>' según la distro.

    - Debian/Ubuntu: nogroup
    - AlmaLinux/Rocky/CentOS/Fedora: nobody
    """
    os_release = Path("/etc/os-release")
    if os_release.exists():
        data = os_release.read_text(encoding="utf-8", errors="ignore").lower()
        if "ubuntu" in data or "debian" in data:
            return "nogroup"
        if any(x in data for x in ["almalinux", "rocky", "centos", "fedora"]):
            return "nobody"
    # Predeterminado razonable
    return "nogroup"


def ensure_paths() -> None:
    missing: List[Path] = []
    for p in [SERVER_CONF, EASYRSA_DIR, CLIENT_TEMPLATE, PKI_DIR]:
        if not p.exists():
            missing.append(p)
    if missing:
        raise CliError(
            "Faltan rutas necesarias: " + ", ".join(str(p) for p in missing)
        )


def filter_out_comment_lines(lines: Iterable[str]) -> List[str]:
    out: List[str] = []
    for line in lines:
        if line.lstrip().startswith("#"):
            continue
        out.append(line)
    return out


def build_client(cn: str, days: int) -> None:
    if not re.fullmatch(r"[0-9A-Za-z_-]+", cn):
        raise CliError(
            "Nombre de cliente inválido. Use solo letras, números, _ y -."
        )
    cmd = [
        "./easyrsa",
        "--batch",
        f"--days={days}",
        "build-client-full",
        cn,
        "nopass",
    ]
    run_cmd(cmd, cwd=EASYRSA_DIR)


def build_ovpn_file(cn: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    inline_file = CLIENT_INLINE_DIR / f"{cn}.inline"
    if not inline_file.exists():
        raise CliError(
            f"No se encontró el perfil inline para {cn}: {inline_file}"
        )
    template = CLIENT_TEMPLATE.read_text(encoding="utf-8", errors="ignore").splitlines(True)
    inline = inline_file.read_text(encoding="utf-8", errors="ignore").splitlines(True)
    merged = filter_out_comment_lines(template) + filter_out_comment_lines(inline)
    out_path = out_dir / f"{cn}.ovpn"
    out_path.write_text("".join(merged), encoding="utf-8")
    return out_path


def revoke_client(cn: str) -> None:
    run_cmd(["./easyrsa", "--batch", "revoke", cn], cwd=EASYRSA_DIR)
    # Generar CRL y aplicar
    run_cmd(["./easyrsa", "--batch", "--days=3650", "gen-crl"], cwd=EASYRSA_DIR)
    if not CRL_SOURCE.exists():
        raise CliError(f"No se generó CRL: {CRL_SOURCE}")
    shutil.copy2(CRL_SOURCE, CRL_TARGET)
    group_name = detect_group_name()
    # Propietario: nobody:group_name
    run_cmd(["chown", f"nobody:{group_name}", str(CRL_TARGET)])


@dataclass
class PkiEntry:
    status: str  # V o R
    not_after: Optional[datetime]
    revoked_at: Optional[datetime]
    common_name: str


def _parse_easyrsa_time(raw: str) -> Optional[datetime]:
    raw = raw.strip()
    if not raw:
        return None
    # Formato típico: YYMMDDHHMMSSZ
    try:
        return datetime.strptime(raw, "%y%m%d%H%M%SZ")
    except ValueError:
        return None


def parse_index() -> List[PkiEntry]:
    index_path = PKI_DIR / "index.txt"
    if not index_path.exists():
        raise CliError(f"No existe índice PKI: {index_path}")
    entries: List[PkiEntry] = []
    for line in index_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        status = parts[0]
        not_after_raw = parts[1]
        revoked_raw = parts[2] if status == "R" else ""
        subject = parts[-1]
        m = re.search(r"/CN=([^/]+)", subject)
        if not m:
            continue
        cn = m.group(1)
        entries.append(
            PkiEntry(
                status=status,
                not_after=_parse_easyrsa_time(not_after_raw),
                revoked_at=_parse_easyrsa_time(revoked_raw),
                common_name=cn,
            )
        )
    return entries


def list_connected() -> List[dict]:
    if not STATUS_LOG.exists():
        raise CliError(
            f"No existe el archivo de estado: {STATUS_LOG}. Ejecute setup-status primero."
        )
    lines = STATUS_LOG.read_text(encoding="utf-8", errors="ignore").splitlines()
    clients: List[dict] = []
    in_client_list = False
    reader: Optional[csv.reader] = None
    # openvpn-status.log v2 es CSV con encabezados simples por bloque
    for line in lines:
        if line.strip() == "CLIENT LIST":
            in_client_list = True
            continue
        if line.strip() in ("ROUTING TABLE", "GLOBAL STATS", "END"):
            in_client_list = False
        if not in_client_list:
            continue
        if not line or line.startswith("Updated,"):
            continue
        # Formato esperado: Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since,Virtual Address
        row = [c.strip() for c in line.split(",")]
        if len(row) < 5:
            continue
        common_name = row[0]
        real_address = row[1]
        bytes_received = int(row[2]) if row[2].isdigit() else None
        bytes_sent = int(row[3]) if row[3].isdigit() else None
        connected_since = row[4]
        virtual_address = row[5] if len(row) > 5 else None
        clients.append(
            {
                "name": common_name,
                "real_address": real_address,
                "virtual_address": virtual_address,
                "bytes_received": bytes_received,
                "bytes_sent": bytes_sent,
                "connected_since": connected_since,
            }
        )
    return clients


def ensure_status_lines() -> bool:
    """Asegura que server.conf contiene status v2. Devuelve True si hubo cambios."""
    ensure_paths()
    content = SERVER_CONF.read_text(encoding="utf-8", errors="ignore")
    need_status = "status /etc/openvpn/server/openvpn-status.log" not in content
    need_version = "status-version 2" not in content
    if not (need_status or need_version):
        return False
    to_append = []
    if need_status:
        to_append.append("status /etc/openvpn/server/openvpn-status.log\n")
    if need_version:
        to_append.append("status-version 2\n")
    # Asegurar salto de línea previo
    if not content.endswith("\n"):
        content += "\n"
    SERVER_CONF.write_text(content + "".join(to_append), encoding="utf-8")
    return True


def reload_openvpn_service() -> None:
    # Algunos sistemas no soportan 'reload' para esta unidad.
    # Intentar 'try-reload-or-restart' y, si falla, forzar 'restart'.
    try:
        run_cmd(["systemctl", "try-reload-or-restart", "openvpn-server@server"])
    except CliError:
        run_cmd(["systemctl", "restart", "openvpn-server@server"])


def cmd_add(args: argparse.Namespace) -> None:
    require_root()
    ensure_paths()
    days = 3650
    build_client(args.name, days)
    out_path = build_ovpn_file(args.name, Path(args.out))
    print(f"OK: cliente '{args.name}' creado. Perfil: {out_path}")


def cmd_add_temp(args: argparse.Namespace) -> None:
    require_root()
    ensure_paths()
    days = int(args.days)
    if days <= 0:
        raise CliError("--days debe ser > 0")
    build_client(args.name, days)
    out_path = build_ovpn_file(args.name, Path(args.out))
    print(
        f"OK: cliente temporal '{args.name}' creado por {days} días. Perfil: {out_path}"
    )


def cmd_revoke(args: argparse.Namespace) -> None:
    require_root()
    ensure_paths()
    revoke_client(args.name)
    print(f"OK: cliente '{args.name}' revocado y CRL actualizado.")


def cmd_list(args: argparse.Namespace) -> None:
    ensure_paths()
    entries = parse_index()
    # Salida simple en columnas
    print(f"{'STATUS':6} {'EXPIRES':20} {'REVOKED':20} NAME")
    for e in entries:
        status = "VALID" if e.status == "V" else ("REVOKED" if e.status == "R" else e.status)
        expires = e.not_after.strftime("%Y-%m-%d %H:%M:%S") if e.not_after else ""
        revoked = e.revoked_at.strftime("%Y-%m-%d %H:%M:%S") if e.revoked_at else ""
        print(f"{status:6} {expires:20} {revoked:20} {e.common_name}")


def cmd_connected(args: argparse.Namespace) -> None:
    clients = list_connected()
    if not clients:
        print("No hay clientes conectados.")
        return
    print(f"{'NAME':25} {'REAL_ADDR':22} {'VIRTUAL':18} {'RX':10} {'TX':10} {'SINCE'}")
    for c in clients:
        name = c.get("name", "")
        real_addr = c.get("real_address", "")
        virt = c.get("virtual_address", "") or ""
        rx = c.get("bytes_received")
        tx = c.get("bytes_sent")
        since = c.get("connected_since", "")
        print(
            f"{name:25} {real_addr:22} {virt:18} {str(rx or ''):10} {str(tx or ''):10} {since}"
        )


def cmd_setup_status(args: argparse.Namespace) -> None:
    require_root()
    changed = ensure_status_lines()
    if changed:
        reload_openvpn_service()
        print(
            "Directivas de estado añadidas a server.conf y servicio recargado/reiniciado."
        )
    else:
        print("Las directivas de estado ya están presentes. Nada que hacer.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CLI de administración de OpenVPN",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="Crear cliente permanente y generar .ovpn")
    p_add.add_argument("--name", required=True, help="Nombre del cliente (CN)")
    p_add.add_argument(
        "--out", default=str(Path.cwd()), help="Directorio de salida para el .ovpn"
    )
    p_add.set_defaults(func=cmd_add)

    p_addt = sub.add_parser(
        "add-temp", help="Crear cliente temporal por N días y generar .ovpn"
    )
    p_addt.add_argument("--name", required=True, help="Nombre del cliente (CN)")
    p_addt.add_argument("--days", required=True, type=int, help="Días de validez")
    p_addt.add_argument(
        "--out", default=str(Path.cwd()), help="Directorio de salida para el .ovpn"
    )
    p_addt.set_defaults(func=cmd_add_temp)

    p_rev = sub.add_parser("revoke", help="Revocar/bloquear un cliente")
    p_rev.add_argument("--name", required=True, help="Nombre del cliente (CN)")
    p_rev.set_defaults(func=cmd_revoke)

    p_list = sub.add_parser("list", help="Listar clientes (válidos/revocados)")
    p_list.set_defaults(func=cmd_list)

    p_conn = sub.add_parser("connected", help="Listar clientes conectados")
    p_conn.set_defaults(func=cmd_connected)

    p_status = sub.add_parser(
        "setup-status",
        help="Asegurar status en server.conf y recargar servicio",
    )
    p_status.set_defaults(func=cmd_setup_status)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except CliError as e:
        print(f"ERROR: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()


