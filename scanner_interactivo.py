#!/usr/bin/env python3
"""
Escáner de Puertos Interactivo
Permite al usuario elegir el objetivo y puertos mediante argumentos
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

def get_service_name(port):
    """Retorna nombre del servicio"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
    }
    return services.get(port, "Unknown")

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
    
    parser.add_argument('-o', '--output',
                       help='Archivo de salida para guardar resultados')
    
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
    results = []
    
    for i, port in enumerate(ports, 1):
        is_open = scan_port(args.target, port, args.timeout)
        
        if is_open:
            service = get_service_name(port)
            print(f"[+] Puerto {port:5d} ABIERTO - {service}")
            open_ports.append((port, service))
            results.append(f"Puerto {port:5d} ABIERTO - {service}")
        elif args.verbose:
            print(f"[-] Puerto {port:5d} cerrado")
            results.append(f"Puerto {port:5d} cerrado")
        else:
            print(f"Progreso: {i}/{len(ports)}", end='\r')
    
    # Resumen
    print("\n" + "="*60)
    print("📊 RESUMEN")
    print("="*60)
    print(f"✅ Puertos abiertos: {len(open_ports)}/{len(ports)}")
    print(f"🕐 Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if open_ports:
        print(f"\n🔓 Puertos abiertos: {', '.join(str(p[0]) for p in open_ports)}")
    
    # Guardar en archivo si se especificó
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"Escaneo de puertos - {datetime.now()}\n")
            f.write(f"Objetivo: {args.target}\n")
            f.write(f"Puertos escaneados: {len(ports)}\n")
            f.write(f"Puertos abiertos: {len(open_ports)}\n\n")
            f.write("-"*50 + "\n")
            for result in results:
                f.write(result + "\n")
        print(f"\n💾 Resultados guardados en: {args.output}")

if __name__ == "__main__":
    main()
