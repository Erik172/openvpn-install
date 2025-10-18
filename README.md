## openvpn-install (Fork con CLI de administración en Python)

Este repositorio es un fork de [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install), publicado bajo licencia MIT. Mantiene intacto el instalador original `openvpn-install.sh` y añade un CLI de administración en Python para gestionar clientes y sesiones de OpenVPN desde el servidor.

### ¿Qué aporta este fork?

- `ovpn_admin.py`: herramienta de línea de comandos para:
  - Crear nuevos clientes permanentes
  - Crear clientes temporales (certificados con caducidad de X días)
  - Revocar/bloquear clientes (actualiza la CRL)
  - Listar clientes (válidos y revocados) con fechas de expiración
  - Ver clientes conectados en tiempo real (requiere estado activado)
  - Configurar directivas de estado en `server.conf` y recargar el servicio

El instalador original no se modifica. Este CLI opera sobre la estructura creada por `openvpn-install.sh` en `/etc/openvpn/server/`.

### Requisitos

- Servidor Linux compatible (Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS o Fedora)
- OpenVPN instalado con el script oficial (`openvpn-install.sh`)
- Python 3 disponible en el servidor
- Privilegios de superusuario para las operaciones administrativas (usar `sudo`)

### Instalación del servidor OpenVPN (upstream)

Ejecuta el instalador original y sigue el asistente:

```bash
wget https://git.io/vpn -O openvpn-install.sh && bash openvpn-install.sh
```

Una vez instalado, podrás volver a ejecutar el script para añadir/eliminar clientes o desinstalar OpenVPN. Consulta el proyecto original: [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install).

### CLI de administración: ovpn_admin.py

El CLI se encuentra en la raíz del repositorio. Proporciona varios subcomandos:

- Crear cliente permanente y generar perfil `.ovpn`:
  ```bash
  sudo python3 ovpn_admin.py add --name alice --out ./
  ```

- Crear cliente temporal por N días y generar perfil `.ovpn`:
  ```bash
  sudo python3 ovpn_admin.py add-temp --name alice-temp --days 7 --out ./
  ```

- Revocar/bloquear un cliente y actualizar la CRL:
  ```bash
  sudo python3 ovpn_admin.py revoke --name alice
  ```

- Listar clientes (válidos/revocados) desde la PKI (`index.txt`):
  ```bash
  sudo python3 ovpn_admin.py list
  ```

- Ver clientes conectados (requiere estado activado):
  ```bash
  sudo python3 ovpn_admin.py connected
  ```

- Activar estado (si falta) y recargar el servicio:
  ```bash
  sudo python3 ovpn_admin.py setup-status
  ```

#### Notas sobre clientes conectados

Para que `connected` funcione, `server.conf` debe incluir:

```
status /etc/openvpn/server/openvpn-status.log
status-version 2
```

El subcomando `setup-status` añade estas directivas si no existen y ejecuta `systemctl reload openvpn-server@server`.

### Estructura esperada (por defecto)

- `/etc/openvpn/server/server.conf`: configuración del servidor
- `/etc/openvpn/server/easy-rsa/`: PKI de easy-rsa
- `/etc/openvpn/server/easy-rsa/pki/index.txt`: índice de certificados
- `/etc/openvpn/server/easy-rsa/pki/inline/private/<CN>.inline`: perfil inline del cliente
- `/etc/openvpn/server/client-common.txt`: plantilla de cliente
- `/etc/openvpn/server/openvpn-status.log`: estado en vivo (si está activado)

### Seguridad y buenas prácticas

- Usa nombres de cliente (CN) con caracteres seguros: letras, números, `_` y `-`.
- Para accesos temporales, prefiere certificados con caducidad corta (subcomando `add-temp`).
- Revoca de inmediato cualquier cliente comprometido (`revoke`).
- Asegura permisos correctos sobre `crl.pem` y archivos de la PKI.

### Problemas comunes

- «Permiso denegado» o fallos al copiar/recargar: ejecuta siempre el CLI con `sudo`.
- No aparecen clientes conectados: ejecuta primero `setup-status` y espera a que el estado se actualice.
- Errores de `easy-rsa`: verifica que la ruta `/etc/openvpn/server/easy-rsa/` existe y contiene `./easyrsa`.

### Créditos y licencia

Este proyecto es un fork de [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install). El trabajo original y este fork se publican bajo la licencia MIT. Consulta el archivo `LICENSE.txt` en este repositorio para los términos completos.
