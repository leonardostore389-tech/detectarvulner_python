# 🔐 GUÍA COMPLETA: Escáner de Vulnerabilidades de Red

## 📋 ÍNDICE
1. [Requisitos Previos](#requisitos-previos)
2. [Fase 1: Preparación del Entorno](#fase-1-preparación-del-entorno)
3. [Fase 2: Escáner Básico de Puertos](#fase-2-escáner-básico-de-puertos)
4. [Fase 3: Escáner Avanzado con Scapy](#fase-3-escáner-avanzado-con-scapy)
5. [Fase 4: Integración con SQL Server](#fase-4-integración-con-sql-server)
6. [Fase 5: Generación de Reportes](#fase-5-generación-de-reportes)
7. [Fase 6: Dashboard Web (Bonus)](#fase-6-dashboard-web-bonus)
8. [Recursos y Mejores Prácticas](#recursos-y-mejores-prácticas)

---

## ⚠️ ADVERTENCIA LEGAL

**IMPORTANTE:** Este proyecto es SOLO para propósitos educativos y de seguridad ética.

- ✅ **PERMITIDO:** Escanear tu propia red doméstica o de laboratorio
- ✅ **PERMITIDO:** Usar en máquinas virtuales de tu propiedad
- ✅ **PERMITIDO:** Practicar en plataformas autorizadas (HackTheBox, TryHackMe)
- ❌ **PROHIBIDO:** Escanear redes de terceros sin autorización escrita
- ❌ **PROHIBIDO:** Usar en entornos de producción sin permiso
- ❌ **ILEGAL:** Acceder a sistemas sin autorización

**El uso indebido puede resultar en consecuencias legales graves.**

---

## 📦 REQUISITOS PREVIOS

### Hardware Mínimo
- **CPU:** 2 núcleos
- **RAM:** 4 GB
- **Disco:** 20 GB libres
- **Red:** Conexión Ethernet o WiFi

### Software Necesario
- **Sistema Operativo:** Linux (Ubuntu 20.04+ recomendado) o VirtualBox con Linux
- **Python:** Versión 3.8 o superior
- **SQL Server:** Express Edition o Developer Edition (opcional para fase 4)
- **Permisos:** Acceso root/sudo

---

## 🚀 FASE 1: PREPARACIÓN DEL ENTORNO

### Paso 1.1: Actualizar el Sistema

```bash
# Actualizar repositorios
sudo apt update

# Actualizar paquetes instalados
sudo apt upgrade -y
```

### Paso 1.2: Instalar Python y Pip

```bash
# Verificar versión de Python (debe ser 3.8+)
python3 --version

# Instalar pip si no está instalado
sudo apt install python3-pip -y

# Verificar instalación
pip3 --version
```

### Paso 1.3: Instalar Nmap

```bash
# Instalar Nmap
sudo apt install nmap -y

# Verificar instalación
nmap --version
```

### Paso 1.4: Instalar Librerías Python

```bash
# Crear directorio del proyecto
mkdir ~/network-scanner
cd ~/network-scanner

# Crear entorno virtual (recomendado)
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias
pip3 install scapy python-nmap

# Para SQL Server (opcional)
pip3 install pyodbc

# Dependencias adicionales útiles
pip3 install colorama tabulate
```

### Paso 1.5: Configurar Permisos para Scapy

```bash
# Scapy requiere privilegios de root para ciertos escaneos
# Opción 1: Ejecutar siempre con sudo
# Opción 2: Dar capacidades especiales a Python (más seguro)
sudo setcap cap_net_raw=eip /usr/bin/python3.8
```

### Paso 1.6: Verificar Instalación

```bash
# Crear script de prueba
cat > test_install.py << 'EOF'
import socket
import scapy.all as scapy
import nmap

print("✅ Socket disponible")
print("✅ Scapy versión:", scapy.__version__)
print("✅ Python-nmap instalado")
print("✅ Todo listo para comenzar!")
EOF

# Ejecutar prueba
python3 test_install.py
```

**Resultado esperado:**
```
✅ Socket disponible
✅ Scapy versión: 2.x.x
✅ Python-nmap instalado
✅ Todo listo para comenzar!
```

---

## 🔍 FASE 2: ESCÁNER BÁSICO DE PUERTOS

### Paso 2.1: Crear el Escáner Simple

Crea el archivo `scanner_basico.py`:

```python
#!/usr/bin/env python3
"""
Escáner Básico de Puertos
Autor: Tu Nombre
Descripción: Escanea puertos TCP comunes en un host objetivo
"""

import socket
from datetime import datetime
import sys

def banner():
    """Mostrar banner del programa"""
    print("="*50)
    print("  ESCÁNER DE PUERTOS - Versión Básica")
    print("="*50)
    print()

def scan_port(ip, port, timeout=1):
    """
    Escanea un puerto específico en una IP
    
    Args:
        ip (str): Dirección IP objetivo
        port (int): Puerto a escanear
        timeout (int): Tiempo de espera en segundos
    
    Returns:
        bool: True si el puerto está abierto
    """
    try:
        # Crear socket TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Intentar conectar
        result = sock.connect_ex((ip, port))
        sock.close()
        
        return result == 0  # 0 = puerto abierto
    
    except socket.gaierror:
        print(f"❌ Error: No se pudo resolver el hostname {ip}")
        return False
    except socket.error:
        print(f"❌ Error: No se pudo conectar a {ip}")
        return False

def get_service_name(port):
    """Obtener nombre del servicio por número de puerto"""
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt"
    }
    return services.get(port, "Desconocido")

def scan_target(target_ip, ports):
    """
    Escanea múltiples puertos en un objetivo
    
    Args:
        target_ip (str): IP objetivo
        ports (list): Lista de puertos a escanear
    """
    banner()
    
    print(f"🎯 Objetivo: {target_ip}")
    print(f"🕐 Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📊 Puertos a escanear: {len(ports)}")
    print("-"*50)
    print()
    
    open_ports = []
    
    for port in ports:
        if scan_port(target_ip, port):
            service = get_service_name(port)
            print(f"[+] Puerto {port:5d} ABIERTO  - {service}")
            open_ports.append((port, service))
        else:
            print(f"[-] Puerto {port:5d} cerrado", end='\r')
    
    print("\n")
    print("="*50)
    print(f"📊 RESUMEN DEL ESCANEO")
    print("="*50)
    print(f"✅ Puertos abiertos: {len(open_ports)}")
    print(f"❌ Puertos cerrados: {len(ports) - len(open_ports)}")
    print(f"🕐 Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if open_ports:
        print("\n🔓 PUERTOS ABIERTOS DETECTADOS:")
        print("-"*50)
        for port, service in open_ports:
            print(f"  Puerto {port:5d} - {service}")

def main():
    """Función principal"""
    # Configuración
    target = "127.0.0.1"  # CAMBIAR por tu IP objetivo
    
    # Puertos comunes a escanear
    common_ports = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        8080,  # HTTP-Proxy
        8443   # HTTPS-Alt
    ]
    
    try:
        scan_target(target, common_ports)
    except KeyboardInterrupt:
        print("\n\n⚠️  Escaneo interrumpido por el usuario")
        sys.exit(0)

if __name__ == "__main__":
    main()
```

### Paso 2.2: Ejecutar el Escáner Básico

```bash
# Dar permisos de ejecución
chmod +x scanner_basico.py

# Ejecutar (cambia la IP en el código primero)
python3 scanner_basico.py

# O escanear localhost para pruebas
python3 scanner_basico.py
```

### Paso 2.3: Mejorar el Escáner (Versión Interactiva)

Crea `scanner_interactivo.py`:

```python
#!/usr/bin/env python3
"""
Escáner de Puertos Interactivo
Permite al usuario elegir el objetivo y puertos
"""

import socket
from datetime import datetime
import argparse
import sys

def scan_port(ip, port, timeout=1):
    """Escanea un puerto específico"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def parse_ports(port_str):
    """
    Parsea una cadena de puertos en lista
    Ejemplos: "80,443,8080" o "1-100" o "80,443,1000-2000"
    """
    ports = []
    
    for part in port_str.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(set(ports))

def main():
    """Función principal con argumentos"""
    parser = argparse.ArgumentParser(
        description='Escáner de Puertos TCP',
        epilog='Ejemplo: python3 scanner_interactivo.py -t 192.168.1.1 -p 80,443,8080'
    )
    
    parser.add_argument('-t', '--target', 
                       required=True,
                       help='IP o hostname objetivo')
    
    parser.add_argument('-p', '--ports',
                       default='21,22,23,25,80,443,3306,3389,8080',
                       help='Puertos a escanear (ej: 80,443 o 1-1000)')
    
    parser.add_argument('--timeout',
                       type=float,
                       default=1.0,
                       help='Timeout en segundos (default: 1.0)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Modo verbose (mostrar puertos cerrados)')
    
    args = parser.parse_args()
    
    # Parsear puertos
    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print("❌ Error: Formato de puertos inválido")
        sys.exit(1)
    
    # Banner
    print("="*60)
    print("  ESCÁNER DE PUERTOS TCP - Versión Interactiva")
    print("="*60)
    print(f"🎯 Objetivo: {args.target}")
    print(f"📊 Puertos: {len(ports)}")
    print(f"⏱️  Timeout: {args.timeout}s")
    print(f"🕐 Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*60)
    
    open_ports = []
    
    for i, port in enumerate(ports, 1):
        is_open = scan_port(args.target, port, args.timeout)
        
        if is_open:
            print(f"[+] Puerto {port:5d} ABIERTO")
            open_ports.append(port)
        elif args.verbose:
            print(f"[-] Puerto {port:5d} cerrado")
        else:
            print(f"Progreso: {i}/{len(ports)}", end='\r')
    
    # Resumen
    print("\n" + "="*60)
    print("📊 RESUMEN")
    print("="*60)
    print(f"✅ Puertos abiertos: {len(open_ports)}/{len(ports)}")
    print(f"🕐 Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if open_ports:
        print(f"\n🔓 Puertos abiertos: {', '.join(map(str, open_ports))}")

if __name__ == "__main__":
    main()
```

### Paso 2.4: Ejemplos de Uso

```bash
# Escanear localhost puertos comunes
python3 scanner_interactivo.py -t 127.0.0.1

# Escanear un rango de puertos
python3 scanner_interactivo.py -t 192.168.1.1 -p 1-100

# Escanear puertos específicos con timeout mayor
python3 scanner_interactivo.py -t 192.168.1.1 -p 80,443,8080 --timeout 2

# Modo verbose
python3 scanner_interactivo.py -t 192.168.1.1 -p 80,443 -v
```

---

## 🎯 FASE 3: ESCÁNER AVANZADO CON SCAPY

### Paso 3.1: Crear Escáner de Red (ARP)

Crea `scanner_red.py`:

```python
#!/usr/bin/env python3
"""
Escáner de Red con Scapy
Descubre dispositivos activos en la red local
"""

from scapy.all import ARP, Ether, srp
import argparse
from datetime import datetime

def scan_network(network):
    """
    Escanea la red usando ARP
    
    Args:
        network (str): Rango de red (ej: 192.168.1.0/24)
    
    Returns:
        list: Lista de dispositivos encontrados
    """
    print(f"🔍 Escaneando red: {network}")
    print("Por favor espera...")
    
    # Crear paquete ARP
    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    
    # Enviar y recibir respuestas
    result = srp(packet, timeout=3, verbose=0)[0]
    
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc
        })
    
    return devices

def get_vendor(mac):
    """
    Intenta identificar el fabricante por MAC
    (Simplificado - en producción usar base de datos OUI)
    """
    # Primeros 3 octetos identifican al fabricante
    oui = mac[:8].upper()
    
    vendors = {
        '00:0C:29': 'VMware',
        '08:00:27': 'VirtualBox',
        'DC:A6:32': 'Raspberry Pi',
        # Agregar más según necesites
    }
    
    return vendors.get(oui, 'Desconocido')

def main():
    parser = argparse.ArgumentParser(description='Escáner de Red Local (ARP)')
    parser.add_argument('-n', '--network',
                       default='192.168.1.0/24',
                       help='Rango de red a escanear (default: 192.168.1.0/24)')
    parser.add_argument('-o', '--output',
                       help='Archivo de salida (opcional)')
    
    args = parser.parse_args()
    
    # Banner
    print("="*70)
    print("  ESCÁNER DE RED - ARP Discovery")
    print("="*70)
    print(f"🕐 Inicio: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Escanear
    devices = scan_network(args.network)
    
    # Mostrar resultados
    if devices:
        print(f"\n✅ {len(devices)} dispositivos encontrados:\n")
        print(f"{'IP':<15} {'MAC':<18} {'Fabricante':<20}")
        print("-"*70)
        
        for device in devices:
            vendor = get_vendor(device['mac'])
            print(f"{device['ip']:<15} {device['mac']:<18} {vendor:<20}")
        
        # Guardar en archivo si se especificó
        if args.output:
            with open(args.output, 'w') as f:
                f.write(f"Escaneo de red - {datetime.now()}\n")
                f.write(f"Red: {args.network}\n\n")
                f.write(f"{'IP':<15} {'MAC':<18}\n")
                f.write("-"*35 + "\n")
                for device in devices:
                    f.write(f"{device['ip']:<15} {device['mac']:<18}\n")
            print(f"\n💾 Resultados guardados en: {args.output}")
    else:
        print("\n❌ No se encontraron dispositivos")
    
    print(f"\n🕐 Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
```

### Paso 3.2: Ejecutar Escáner de Red

```bash
# Requiere privilegios root
sudo python3 scanner_red.py

# Especificar red diferente
sudo python3 scanner_red.py -n 10.0.0.0/24

# Guardar resultados
sudo python3 scanner_red.py -o dispositivos.txt
```

---

## 💾 FASE 4: INTEGRACIÓN CON SQL SERVER

### Paso 4.1: Instalar SQL Server en Linux

```bash
# Importar clave GPG
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# Agregar repositorio
sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/mssql-server-2019.list)"

# Instalar SQL Server
sudo apt-get update
sudo apt-get install -y mssql-server

# Configurar SQL Server
sudo /opt/mssql/bin/mssql-conf setup

# Instalar herramientas de línea de comandos
sudo apt-get install mssql-tools unixodbc-dev

# Agregar al PATH
echo 'export PATH="$PATH:/opt/mssql-tools/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Paso 4.2: Crear Base de Datos

```bash
# Conectar a SQL Server
sqlcmd -S localhost -U sa -P 'TuContraseñaSegura123!'
```

```sql
-- Crear base de datos
CREATE DATABASE SecurityScans;
GO

USE SecurityScans;
GO

-- Tabla para almacenar escaneos
CREATE TABLE scans (
    id INT IDENTITY(1,1) PRIMARY KEY,
    scan_date DATETIME DEFAULT GETDATE(),
    target_ip VARCHAR(15) NOT NULL,
    target_network VARCHAR(20),
    scan_type VARCHAR(50)
);
GO

-- Tabla para resultados de puertos
CREATE TABLE port_results (
    id INT IDENTITY(1,1) PRIMARY KEY,
    scan_id INT FOREIGN KEY REFERENCES scans(id),
    port INT NOT NULL,
    status VARCHAR(10) NOT NULL,
    service VARCHAR(50),
    detected_date DATETIME DEFAULT GETDATE()
);
GO

-- Tabla para dispositivos de red
CREATE TABLE network_devices (
    id INT IDENTITY(1,1) PRIMARY KEY,
    scan_id INT FOREIGN KEY REFERENCES scans(id),
    ip_address VARCHAR(15) NOT NULL,
    mac_address VARCHAR(18),
    vendor VARCHAR(100),
    discovered_date DATETIME DEFAULT GETDATE()
);
GO

-- Índices para mejorar rendimiento
CREATE INDEX idx_scans_date ON scans(scan_date);
CREATE INDEX idx_port_results_scan ON port_results(scan_id);
CREATE INDEX idx_devices_scan ON network_devices(scan_id);
GO
```

### Paso 4.3: Script con Integración SQL

Crea `scanner_con_bd.py`:

```python
#!/usr/bin/env python3
"""
Escáner de Puertos con Almacenamiento en SQL Server
"""

import socket
import pyodbc
from datetime import datetime
import argparse

# Configuración de la base de datos
DB_CONFIG = {
    'server': 'localhost',
    'database': 'SecurityScans',
    'username': 'sa',
    'password': 'TuContraseñaSegura123!'  # CAMBIAR
}

def get_db_connection():
    """Establece conexión con SQL Server"""
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={DB_CONFIG['server']};"
        f"DATABASE={DB_CONFIG['database']};"
        f"UID={DB_CONFIG['username']};"
        f"PWD={DB_CONFIG['password']}"
    )
    return pyodbc.connect(conn_str)

def create_scan_record(conn, target_ip, scan_type='port_scan'):
    """Crea registro de escaneo y retorna el ID"""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scans (target_ip, scan_type) VALUES (?, ?)",
        (target_ip, scan_type)
    )
    conn.commit()
    
    # Obtener ID del escaneo creado
    cursor.execute("SELECT SCOPE_IDENTITY()")
    scan_id = cursor.fetchone()[0]
    return int(scan_id)

def save_port_result(conn, scan_id, port, status, service):
    """Guarda resultado de escaneo de puerto"""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO port_results (scan_id, port, status, service) VALUES (?, ?, ?, ?)",
        (scan_id, port, status, service)
    )
    conn.commit()

def scan_port(ip, port, timeout=1):
    """Escanea un puerto"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_service_name(port):
    """Retorna nombre del servicio"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        8080: "HTTP-Proxy"
    }
    return services.get(port, "Unknown")

def main():
    parser = argparse.ArgumentParser(description='Escáner con BD')
    parser.add_argument('-t', '--target', required=True, help='IP objetivo')
    parser.add_argument('-p', '--ports', default='21,22,80,443,3306', help='Puertos')
    args = parser.parse_args()
    
    ports = [int(p) for p in args.ports.split(',')]
    
    print("="*60)
    print("  ESCÁNER DE PUERTOS CON BASE DE DATOS")
    print("="*60)
    print(f"🎯 Objetivo: {args.target}")
    print(f"💾 Guardando en SQL Server...")
    
    # Conectar a BD
    try:
        conn = get_db_connection()
        print("✅ Conexión a base de datos exitosa")
    except Exception as e:
        print(f"❌ Error conectando a BD: {e}")
        return
    
    # Crear registro de escaneo
    scan_id = create_scan_record(conn, args.target)
    print(f"📝 Escaneo registrado con ID: {scan_id}\n")
    
    # Escanear puertos
    open_ports = 0
    for port in ports:
        is_open = scan_port(args.target, port)
        status = "OPEN" if is_open else "CLOSED"
        service = get_service_name(port) if is_open else None
        
        # Guardar en BD
        save_port_result(conn, scan_id, port, status, service)
        
        if is_open:
            print(f"[+] Puerto {port:5d} ABIERTO - {service}")
            open_ports += 1
    
    conn.close()
    
    print(f"\n✅ Escaneo completado: {open_ports} puertos abiertos")
    print(f"💾 Resultados guardados en la base de datos")

if __name__ == "__main__":
    main()
```

### Paso 4.4: Ejecutar con Base de Datos

```bash
# Asegúrate de tener SQL Server corriendo
sudo systemctl status mssql-server

# Ejecutar escáner
python3 scanner_con_bd.py -t 127.0.0.1 -p 21,22,80,443,3306
```

---

## 📊 FASE 5: GENERACIÓN DE REPORTES

### Paso 5.1: Script de Reportes

Crea `generar_reporte.py`:

```python
#!/usr/bin/env python3
"""
Generador de Reportes desde Base de Datos
"""

import pyodbc
from datetime import datetime, timedelta
from tabulate import tabulate

DB_CONFIG = {
    'server': 'localhost',
    'database': 'SecurityScans',
    'username': 'sa',
    'password': 'TuContraseñaSegura123!'
}

def get_db_connection():
    """Conectar a base de datos"""
    conn_str = (
        f"DRIVER={{ODBC Driver 17 for SQL Server}};"
        f"SERVER={DB_CONFIG['server']};"
        f"DATABASE={DB_CONFIG['database']};"
        f"UID={DB_CONFIG['username']};"
        f"PWD={DB_CONFIG['password']}"
    )
    return pyodbc.connect(conn_str)

def reporte_puertos_abiertos():
    """Genera reporte de puertos abiertos"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT 
            s.target_ip,
            pr.port,
            pr.service,
            pr.detected_date
        FROM port_results pr
        INNER JOIN scans s ON pr.scan_id = s.id
        WHERE pr.status = 'OPEN'
        ORDER BY pr.detected_date DESC
    """
    
    cursor.execute(query)
    rows = cursor.fetchall()
    
    if rows:
        headers = ['IP', 'Puerto', 'Servicio', 'Fecha Detección']
        data = [[row[0], row[1], row[2], row[3].strftime('%Y-%m-%d %H:%M')] for row in rows]
        print("\n📊 REPORTE: PUERTOS ABIERTOS")
        print("="*80)
        print(tabulate(data, headers=headers, tablefmt='grid'))
    else:
        print("❌ No hay datos de puertos abiertos")
    
    conn.close()

def reporte_escaneos_recientes(dias=7):
    """Muestra escaneos de los últimos N días"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    fecha_desde = datetime.now() - timedelta(days=dias)
    
    query = """
        SELECT 
            id,
            target_ip,
            scan_type,
            scan_date,
            (SELECT COUNT(*) FROM port_results WHERE scan_id = s.id AND status = 'OPEN') as puertos_abiertos
        FROM scans s
        WHERE scan_date >= ?
        ORDER BY scan_date DESC
    """
    
    cursor.execute(query, (fecha_desde,))
    rows = cursor.fetchall()
    
    if rows:
        headers = ['ID', 'IP Objetivo', 'Tipo', 'Fecha', 'Puertos Abiertos']
        data = [[row[0], row[1], row[2], row[3].strftime('%Y-%m-%d %H:%M'), row[4]] for row in rows]
        print(f"\n📊 ESCANEOS ÚLTIMOS {dias} DÍAS")
        print("="*80)
        print(tabulate(data, headers=headers, tablefmt='grid'))
    else:
        print(f"❌ No hay escaneos en los últimos {dias} días")
    
    conn.close()

def reporte_estadisticas():
    """Estadísticas generales"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total de escaneos
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_escaneos = cursor.fetchone()[0]
    
    # Total de puertos abiertos detectados
    cursor.execute("SELECT COUNT(*) FROM port_results WHERE status = 'OPEN'")
    total_puertos = cursor.fetchone()[0]
    
    # IP más escaneada
    cursor.execute("""
        SELECT TOP 1 target_ip, COUNT(*) as total
        FROM scans
        GROUP BY target_ip
        ORDER BY total DESC
    """)
    result = cursor.fetchone()
    ip_mas_escaneada = result[0] if result else "N/A"
    
    print("\n📊 ESTADÍSTICAS GENERALES")
    print("="*50)
    print(f"Total de escaneos realizados: {total_escaneos}")
    print(f"Total de puertos abiertos: {total_puertos}")
    print(f"IP más escaneada: {ip_mas_escaneada}")
    
    conn.close()

def menu():
    """Menú de opciones"""
    while True:
        print("\n" + "="*50)
        print("  GENERADOR DE REPORTES - Security Scanner")
        print("="*50)
        print("1. Puertos abiertos detectados")
        print("2. Escaneos recientes (7 días)")
        print("3. Estadísticas generales")
        print("4. Salir")
        print("-"*50)
        
        opcion = input("Selecciona una opción: ")
        
        if opcion == '1':
            reporte_puertos_abiertos()
        elif opcion == '2':
            reporte_escaneos_recientes()
        elif opcion == '3':
            reporte_estadisticas()
        elif opcion == '4':
            print("👋 ¡Hasta luego!")
            break
        else:
            print("❌ Opción inválida")
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    menu()
```

---

## 🌐 FASE 6: DASHBOARD WEB (BONUS)

En esta fase puedes integrar el dashboard HTML que te creé anteriormente con los datos reales de tu base de datos usando Flask o FastAPI.

---

## 📚 RECURSOS Y MEJORES PRÁCTICAS

### Recursos de Aprendizaje
1. **Scapy Documentation:** https://scapy.readthedocs.io
2. **Python for Ethical Hacking:** YouTube
3. **HackTheBox:** https://hackthebox.com (Práctica legal)
4. **TryHackMe:** https://tryhackme.com (Laboratorios)

### Mejores Prácticas
✅ Documenta todos tus escaneos
✅ Obtén autorización escrita antes de escanear
✅ No escanees redes de producción
✅ Usa entornos de laboratorio
✅ Implementa rate limiting
✅ Registra todas las actividades

### Seguridad del Código
- Nunca hardcodees contraseñas
- Usa variables de entorno
- Implementa logging
- Valida entradas del usuario
- Maneja excepciones adecuadamente

---

## 🎓 EJERCICIOS PRÁCTICOS

1. **Ejercicio 1:** Modifica el escáner para detectar servicios específicos
2. **Ejercicio 2:** Implementa escaneo multihilo para mayor velocidad
3. **Ejercicio 3:** Crea alertas por email cuando se detecten puertos críticos abiertos
4. **Ejercicio 4:** Integra con una API de threat intelligence
5. **Ejercicio 5:** Implementa escaneo de vulnerabilidades conocidas (CVE)

---

## 🐛 TROUBLESHOOTING

### Problema: "Permission denied" al usar Scapy
**Solución:** Ejecuta con `sudo` o configura capabilities

### Problema: No se puede conectar a SQL Server
**Solución:** Verifica que el servicio esté corriendo
```bash
sudo systemctl status mssql-server
```

### Problema: Timeout en escaneos
**Solución:** Aumenta el valor de timeout o verifica tu conexión

---

¡Proyecto completado! 🎉
