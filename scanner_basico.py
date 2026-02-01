#!/usr/bin/env python3
"""
Escáner Básico de Puertos
Escanea puertos TCP comunes en un host objetivo
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
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
    # Configuración - CAMBIAR ESTA IP POR TU OBJETIVO
    target = "127.0.0.1"  # localhost para pruebas
    
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
