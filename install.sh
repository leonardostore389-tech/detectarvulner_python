#!/bin/bash

# Script de instalación automática para el proyecto Network Scanner
# Autor: Security Tools
# Fecha: 2024

echo "=========================================="
echo "  INSTALACIÓN DE NETWORK SCANNER"
echo "=========================================="
echo ""

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para imprimir mensajes
print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[i]${NC} $1"
}

# Verificar si se ejecuta como root
if [ "$EUID" -ne 0 ]; then 
    print_error "Este script debe ejecutarse como root (use sudo)"
    exit 1
fi

print_info "Actualizando repositorios del sistema..."
apt update -qq

# Instalar Python 3 y pip
print_info "Verificando instalación de Python 3..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    print_success "Python ya instalado: $PYTHON_VERSION"
else
    print_info "Instalando Python 3..."
    apt install -y python3 python3-pip
    print_success "Python 3 instalado"
fi

# Verificar pip
print_info "Verificando pip..."
if command -v pip3 &> /dev/null; then
    print_success "pip3 ya instalado"
else
    print_info "Instalando pip3..."
    apt install -y python3-pip
    print_success "pip3 instalado"
fi

# Instalar Nmap
print_info "Verificando Nmap..."
if command -v nmap &> /dev/null; then
    NMAP_VERSION=$(nmap --version | head -n1)
    print_success "Nmap ya instalado: $NMAP_VERSION"
else
    print_info "Instalando Nmap..."
    apt install -y nmap
    print_success "Nmap instalado"
fi

# Crear directorio del proyecto
print_info "Creando estructura de directorios..."
mkdir -p ~/network-scanner
cd ~/network-scanner

# Crear entorno virtual
print_info "Creando entorno virtual de Python..."
python3 -m venv venv
print_success "Entorno virtual creado"

# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias Python
print_info "Instalando dependencias de Python..."

# Actualizar pip
pip install --upgrade pip -q

# Instalar paquetes
print_info "Instalando scapy..."
pip install scapy -q

print_info "Instalando python-nmap..."
pip install python-nmap -q

print_info "Instalando colorama..."
pip install colorama -q

print_info "Instalando tabulate..."
pip install tabulate -q

print_success "Todas las dependencias Python instaladas"

# Configurar permisos para Scapy (opcional)
print_info "Configurando permisos para Scapy..."
PYTHON_BIN=$(which python3)
setcap cap_net_raw=eip $PYTHON_BIN 2>/dev/null
if [ $? -eq 0 ]; then
    print_success "Permisos configurados correctamente"
else
    print_info "No se pudieron configurar permisos automáticamente"
    print_info "Necesitarás ejecutar scripts con sudo para usar Scapy"
fi

# Crear archivo de requisitos
print_info "Creando archivo requirements.txt..."
cat > requirements.txt << EOF
scapy>=2.4.5
python-nmap>=0.7.1
colorama>=0.4.4
tabulate>=0.9.0
pyodbc>=4.0.34
EOF
print_success "requirements.txt creado"

# Crear script de prueba
print_info "Creando script de verificación..."
cat > test_installation.py << 'EOF'
#!/usr/bin/env python3
import sys

def test_imports():
    print("="*50)
    print("  VERIFICACIÓN DE INSTALACIÓN")
    print("="*50)
    print()
    
    modules = [
        ('socket', 'Socket (Built-in)'),
        ('scapy.all', 'Scapy'),
        ('nmap', 'Python-nmap'),
        ('colorama', 'Colorama'),
        ('tabulate', 'Tabulate')
    ]
    
    all_ok = True
    
    for module_name, display_name in modules:
        try:
            __import__(module_name)
            print(f"✅ {display_name:<20} - OK")
        except ImportError as e:
            print(f"❌ {display_name:<20} - ERROR: {e}")
            all_ok = False
    
    print()
    if all_ok:
        print("🎉 ¡Todas las dependencias instaladas correctamente!")
        return 0
    else:
        print("⚠️  Algunas dependencias faltan. Revisa los errores arriba.")
        return 1

if __name__ == "__main__":
    sys.exit(test_imports())
EOF

chmod +x test_installation.py
print_success "Script de verificación creado"

# Ejecutar prueba
print_info "Ejecutando prueba de instalación..."
python3 test_installation.py

# Resumen final
echo ""
echo "=========================================="
echo "  INSTALACIÓN COMPLETADA"
echo "=========================================="
print_success "Directorio del proyecto: ~/network-scanner"
print_success "Entorno virtual creado en: ~/network-scanner/venv"
echo ""
print_info "Para activar el entorno virtual:"
echo "  cd ~/network-scanner"
echo "  source venv/bin/activate"
echo ""
print_info "Para ejecutar los scripts:"
echo "  python3 scanner_basico.py"
echo "  python3 scanner_interactivo.py -t 127.0.0.1"
echo ""
print_info "Para scripts con Scapy (requiere privilegios):"
echo "  sudo python3 scanner_red.py"
echo ""
echo "=========================================="
print_success "¡Listo para usar!"
echo "=========================================="
