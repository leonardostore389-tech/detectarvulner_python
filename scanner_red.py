#!/usr/bin/env python3
"""
Escáner de Red con Scapy
Descubre dispositivos activos en la red local usando ARP
NOTA: Requiere privilegios de root/sudo
"""

from scapy.all import ARP, Ether, srp
import argparse
from datetime import datetime
import sys

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
    
    try:
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
    
    except PermissionError:
        print("❌ Error: Este script requiere privilegios de root")
        print("   Ejecuta con: sudo python3 scanner_red.py")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error durante el escaneo: {e}")
        return []

def get_vendor(mac):
    """
    Intenta identificar el fabricante por MAC
    (Simplificado - en producción usar base de datos OUI)
    """
    # Primeros 3 octetos identifican al fabricante
    oui = mac[:8].upper()
    
    # Base de datos simplificada de fabricantes
    vendors = {
        '00:0C:29': 'VMware',
        '08:00:27': 'VirtualBox',
        '00:50:56': 'VMware',
        'DC:A6:32': 'Raspberry Pi',
        'B8:27:EB': 'Raspberry Pi',
        '00:1B:44': 'Cisco',
        '00:24:97': 'Cisco',
        'F0:18:98': 'Apple',
        'AC:DE:48': 'Apple',
        '00:50:F2': 'Microsoft',
        'D4:3D:7E': 'D-Link',
        '00:17:88': 'Philips',
    }
    
    return vendors.get(oui, 'Desconocido')

def save_to_file(devices, filename, network):
    """Guardar resultados en archivo"""
    with open(filename, 'w') as f:
        f.write(f"Escaneo de red - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Red: {network}\n")
        f.write(f"Dispositivos encontrados: {len(devices)}\n")
        f.write("="*70 + "\n\n")
        f.write(f"{'IP':<15} {'MAC':<18} {'Fabricante':<20}\n")
        f.write("-"*70 + "\n")
        
        for device in devices:
            vendor = get_vendor(device['mac'])
            f.write(f"{device['ip']:<15} {device['mac']:<18} {vendor:<20}\n")

def main():
    parser = argparse.ArgumentParser(
        description='Escáner de Red Local (ARP Discovery)',
        epilog='IMPORTANTE: Requiere privilegios de root. Ejecuta con sudo.'
    )
    
    parser.add_argument('-n', '--network',
                       default='192.168.1.0/24',
                       help='Rango de red a escanear (default: 192.168.1.0/24)')
    
    parser.add_argument('-o', '--output',
                       help='Archivo de salida (opcional)')
    
    args = parser.parse_args()
    
    # Verificar si se está ejecutando como root
    import os
    if os.geteuid() != 0:
        print("⚠️  ADVERTENCIA: Este script requiere privilegios de root")
        print("   Ejecuta con: sudo python3 scanner_red.py")
        print()
    
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
            save_to_file(devices, args.output, args.network)
            print(f"\n💾 Resultados guardados en: {args.output}")
    else:
        print("\n❌ No se encontraron dispositivos")
    
    print(f"\n🕐 Finalizado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

if __name__ == "__main__":
    main()
