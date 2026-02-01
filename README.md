# 🔐 Network Vulnerability Scanner

Sistema completo de escaneo de vulnerabilidades de red desarrollado en Python para propósitos educativos y de seguridad ética.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-educational-yellow)

## ⚠️ ADVERTENCIA LEGAL

**IMPORTANTE:** Este proyecto es SOLO para propósitos educativos y de hacking ético.

- ✅ **PERMITIDO:** Escanear tu propia red doméstica o de laboratorio
- ✅ **PERMITIDO:** Usar en máquinas virtuales de tu propiedad
- ✅ **PERMITIDO:** Practicar en plataformas autorizadas (HackTheBox, TryHackMe)



## 📋 Características

### Funcionalidades Principales

- 🔍 **Escaneo de Puertos:** Detecta puertos abiertos y servicios en ejecución
- 🌐 **Descubrimiento de Red:** Identifica dispositivos activos en la red local
- 💾 **Almacenamiento en BD:** Guarda resultados en SQL Server para análisis histórico
- 📊 **Reportes Detallados:** Genera informes completos de los escaneos
- 🎯 **Múltiples Modos:** Básico, interactivo y avanzado con Scapy
- 🚀 **Alta Velocidad:** Escaneos optimizados con control de timeout

### Tipos de Escaneo

1. **Escaneo Básico de Puertos**
   - Escaneo simple de puertos TCP
   - Identificación de servicios comunes
   - Salida formateada y clara

2. **Escaneo Interactivo**
   - Argumentos de línea de comandos
   - Rangos de puertos personalizables
   - Modo verbose opcional
   - Guardado en archivos

3. **Descubrimiento de Red (ARP)**
   - Escaneo completo de red local
   - Detección de direcciones MAC
   - Identificación de fabricantes
   - Mapeo de dispositivos

## 🚀 Instalación Rápida

### Opción 1: Script Automático (Recomendado)

```bash
# Descargar y ejecutar el instalador
chmod +x install.sh
sudo ./install.sh
```

### Opción 2: Instalación Manual

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias del sistema
sudo apt install -y python3 python3-pip nmap

# Crear directorio del proyecto
mkdir ~/network-scanner && cd ~/network-scanner

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias Python
pip install -r requirements.txt
```

## 📦 Dependencias

### Sistema
- Python 3.8 o superior
- Nmap
- SQL Server (opcional, para persistencia)

### Python
- `scapy` - Manipulación de paquetes de red
- `python-nmap` - Interfaz Python para Nmap
- `pyodbc` - Conexión a SQL Server
- `colorama` - Salida colorizada
- `tabulate` - Tablas formateadas

## 🎮 Uso

### 1. Escáner Básico

```bash
# Editar la IP objetivo en scanner_basico.py
# Luego ejecutar:
python3 scanner_basico.py
```

### 2. Escáner Interactivo

```bash
# Escanear localhost
python3 scanner_interactivo.py -t 127.0.0.1

# Escanear IP específica con puertos personalizados
python3 scanner_interactivo.py -t 192.168.1.1 -p 80,443,8080

# Escanear rango de puertos
python3 scanner_interactivo.py -t 192.168.1.1 -p 1-1000

# Modo verbose con guardado
python3 scanner_interactivo.py -t 192.168.1.1 -p 21,22,80,443 -v -o resultados.txt

# Ajustar timeout
python3 scanner_interactivo.py -t 192.168.1.1 --timeout 2.0
```

### 3. Descubrimiento de Red

```bash
# Requiere privilegios de root
sudo python3 scanner_red.py

# Especificar red diferente
sudo python3 scanner_red.py -n 10.0.0.0/24

# Guardar resultados
sudo python3 scanner_red.py -o dispositivos.txt
```

### 4. Con Base de Datos

```bash
# Primero configurar SQL Server y ejecutar setup_database.sql
# Luego ejecutar el escáner:
python3 scanner_con_bd.py -t 192.168.1.1 -p 21,22,80,443,3306

# Generar reportes
python3 generar_reporte.py
```

## 📁 Estructura del Proyecto

```
network-scanner/
│
├── scanner_basico.py          # Escáner simple de puertos
├── scanner_interactivo.py     # Escáner con argumentos CLI
├── scanner_red.py             # Descubrimiento de red con Scapy
├── scanner_con_bd.py          # Escáner con persistencia en BD
├── generar_reporte.py         # Generador de reportes
│
├── install.sh                 # Script de instalación automática
├── requirements.txt           # Dependencias Python
├── setup_database.sql         # Script de configuración de BD
│
├── GUIA_SCANNER_VULNERABILIDADES.md  # Guía completa paso a paso
└── README.md                  # Este archivo
```

## 🗄️ Configuración de Base de Datos

### Instalar SQL Server en Linux

```bash
# Importar clave GPG
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -

# Agregar repositorio
sudo add-apt-repository "$(wget -qO- https://packages.microsoft.com/config/ubuntu/20.04/mssql-server-2019.list)"

# Instalar
sudo apt-get update
sudo apt-get install -y mssql-server

# Configurar
sudo /opt/mssql/bin/mssql-conf setup
```

### Crear Base de Datos

```bash
# Conectar a SQL Server
sqlcmd -S localhost -U sa -P 'TuPassword'

# Ejecutar script de configuración
:r setup_database.sql
GO
```

## 📊 Ejemplos de Salida

### Escaneo Básico
```
==================================================
  ESCÁNER DE PUERTOS - Versión Básica
==================================================

🎯 Objetivo: 192.168.1.1
🕐 Inicio: 2024-01-15 10:30:00
📊 Puertos a escanear: 15
--------------------------------------------------

[+] Puerto    80 ABIERTO  - HTTP
[+] Puerto   443 ABIERTO  - HTTPS
[+] Puerto    22 ABIERTO  - SSH

==================================================
📊 RESUMEN DEL ESCANEO
==================================================
✅ Puertos abiertos: 3
❌ Puertos cerrados: 12
🕐 Finalizado: 2024-01-15 10:30:15
```

### Descubrimiento de Red
```
======================================================================
  ESCÁNER DE RED - ARP Discovery
======================================================================
🕐 Inicio: 2024-01-15 10:35:00

🔍 Escaneando red: 192.168.1.0/24
Por favor espera...

✅ 5 dispositivos encontrados:

IP              MAC                Fabricante          
----------------------------------------------------------------------
192.168.1.1     00:11:22:33:44:55  Cisco
192.168.1.10    AA:BB:CC:DD:EE:FF  Apple
192.168.1.50    08:00:27:12:34:56  VirtualBox
```

## 🛡️ Buenas Prácticas de Seguridad

1. **Autorización:** Siempre obtén permiso por escrito antes de escanear
2. **Documentación:** Registra todos tus escaneos y hallazgos
3. **Responsabilidad:** Reporta vulnerabilidades de manera responsable
4. **Aislamiento:** Usa entornos de laboratorio separados
5. **Rate Limiting:** No sobrecargues las redes con escaneos agresivos

## 📚 Recursos de Aprendizaje

### Plataformas de Práctica Legal
- [HackTheBox](https://hackthebox.com) - Máquinas virtuales para pentesting
- [TryHackMe](https://tryhackme.com) - Laboratorios guiados
- [VulnHub](https://vulnhub.com) - VMs vulnerables

### Documentación
- [Scapy Documentation](https://scapy.readthedocs.io)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Cursos Recomendados
- Python for Ethical Hacking (YouTube)
- Practical Ethical Hacking (TCM Security)
- Network Security (Coursera)

## 🐛 Troubleshooting

### Problema: "Permission denied" al usar Scapy
**Solución:** Ejecuta con sudo o configura capabilities
```bash
sudo setcap cap_net_raw=eip /usr/bin/python3
```

### Problema: No se puede conectar a SQL Server
**Solución:** Verifica que el servicio esté corriendo
```bash
sudo systemctl status mssql-server
sudo systemctl start mssql-server
```

### Problema: Timeouts en escaneos
**Solución:** Aumenta el timeout
```bash
python3 scanner_interactivo.py -t 192.168.1.1 --timeout 3.0
```

### Problema: "ModuleNotFoundError"
**Solución:** Activa el entorno virtual e instala dependencias
```bash
source venv/bin/activate
pip install -r requirements.txt
```

## 🤝 Contribuciones

Este es un proyecto educativo. Las contribuciones son bienvenidas:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.

## 👨‍💻 Autor

**Tu Nombre**
- GitHub: [@tuusuario](https://github.com/tuusuario)
- LinkedIn: [Tu Perfil](https://linkedin.com/in/tuperfil)

## 🙏 Agradecimientos

- Comunidad de Scapy por la excelente librería
- Fyodor y el equipo de Nmap
- Comunidad de seguridad informática

---

## ⭐ Si este proyecto te fue útil

¡Dale una estrella! ⭐ Ayuda a otros a encontrar este recurso educativo.

---

**Recuerda:** Con gran poder viene gran responsabilidad. Usa estas herramientas de manera ética y legal.
