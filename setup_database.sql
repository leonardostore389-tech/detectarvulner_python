-- ============================================
-- Script de Creación de Base de Datos
-- Sistema de Escaneo de Vulnerabilidades
-- ============================================

-- Crear base de datos
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'SecurityScans')
BEGIN
    CREATE DATABASE SecurityScans;
    PRINT 'Base de datos SecurityScans creada exitosamente';
END
ELSE
BEGIN
    PRINT 'La base de datos SecurityScans ya existe';
END
GO

USE SecurityScans;
GO

-- ============================================
-- Tabla: scans
-- Almacena información general de cada escaneo
-- ============================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[scans]') AND type in (N'U'))
BEGIN
    CREATE TABLE scans (
        id INT IDENTITY(1,1) PRIMARY KEY,
        scan_date DATETIME DEFAULT GETDATE(),
        target_ip VARCHAR(15) NOT NULL,
        target_network VARCHAR(20),
        scan_type VARCHAR(50) NOT NULL,
        duration_seconds INT,
        notes TEXT,
        CONSTRAINT CHK_scan_type CHECK (scan_type IN ('port_scan', 'network_scan', 'vulnerability_scan'))
    );
    PRINT 'Tabla scans creada exitosamente';
END
ELSE
BEGIN
    PRINT 'La tabla scans ya existe';
END
GO

-- ============================================
-- Tabla: port_results
-- Almacena resultados de escaneos de puertos
-- ============================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[port_results]') AND type in (N'U'))
BEGIN
    CREATE TABLE port_results (
        id INT IDENTITY(1,1) PRIMARY KEY,
        scan_id INT NOT NULL,
        port INT NOT NULL,
        status VARCHAR(10) NOT NULL,
        service VARCHAR(50),
        version VARCHAR(100),
        detected_date DATETIME DEFAULT GETDATE(),
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        CONSTRAINT CHK_port CHECK (port > 0 AND port <= 65535),
        CONSTRAINT CHK_status CHECK (status IN ('OPEN', 'CLOSED', 'FILTERED'))
    );
    PRINT 'Tabla port_results creada exitosamente';
END
ELSE
BEGIN
    PRINT 'La tabla port_results ya existe';
END
GO

-- ============================================
-- Tabla: network_devices
-- Almacena dispositivos descubiertos en la red
-- ============================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[network_devices]') AND type in (N'U'))
BEGIN
    CREATE TABLE network_devices (
        id INT IDENTITY(1,1) PRIMARY KEY,
        scan_id INT NOT NULL,
        ip_address VARCHAR(15) NOT NULL,
        mac_address VARCHAR(18),
        hostname VARCHAR(255),
        vendor VARCHAR(100),
        device_type VARCHAR(50),
        discovered_date DATETIME DEFAULT GETDATE(),
        last_seen DATETIME DEFAULT GETDATE(),
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    );
    PRINT 'Tabla network_devices creada exitosamente';
END
ELSE
BEGIN
    PRINT 'La tabla network_devices ya existe';
END
GO

-- ============================================
-- Tabla: vulnerabilities
-- Almacena vulnerabilidades detectadas
-- ============================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[vulnerabilities]') AND type in (N'U'))
BEGIN
    CREATE TABLE vulnerabilities (
        id INT IDENTITY(1,1) PRIMARY KEY,
        scan_id INT NOT NULL,
        target_ip VARCHAR(15) NOT NULL,
        port INT,
        vulnerability_name VARCHAR(255) NOT NULL,
        severity VARCHAR(20),
        cve_id VARCHAR(50),
        description TEXT,
        recommendation TEXT,
        detected_date DATETIME DEFAULT GETDATE(),
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
        CONSTRAINT CHK_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'))
    );
    PRINT 'Tabla vulnerabilities creada exitosamente';
END
ELSE
BEGIN
    PRINT 'La tabla vulnerabilities ya existe';
END
GO

-- ============================================
-- Crear Índices para mejorar rendimiento
-- ============================================
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_scans_date')
BEGIN
    CREATE INDEX idx_scans_date ON scans(scan_date);
    PRINT 'Índice idx_scans_date creado';
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_port_results_scan')
BEGIN
    CREATE INDEX idx_port_results_scan ON port_results(scan_id);
    PRINT 'Índice idx_port_results_scan creado';
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_port_results_status')
BEGIN
    CREATE INDEX idx_port_results_status ON port_results(status);
    PRINT 'Índice idx_port_results_status creado';
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_devices_scan')
BEGIN
    CREATE INDEX idx_devices_scan ON network_devices(scan_id);
    PRINT 'Índice idx_devices_scan creado';
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_devices_ip')
BEGIN
    CREATE INDEX idx_devices_ip ON network_devices(ip_address);
    PRINT 'Índice idx_devices_ip creado';
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_vuln_scan')
BEGIN
    CREATE INDEX idx_vuln_scan ON vulnerabilities(scan_id);
    PRINT 'Índice idx_vuln_scan creado';
END
GO

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_vuln_severity')
BEGIN
    CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
    PRINT 'Índice idx_vuln_severity creado';
END
GO

-- ============================================
-- Vistas útiles
-- ============================================

-- Vista: últimos escaneos
IF EXISTS (SELECT * FROM sys.views WHERE name = 'v_latest_scans')
    DROP VIEW v_latest_scans;
GO

CREATE VIEW v_latest_scans AS
SELECT TOP 100
    s.id,
    s.scan_date,
    s.target_ip,
    s.scan_type,
    s.duration_seconds,
    COUNT(DISTINCT pr.id) as total_ports_scanned,
    COUNT(DISTINCT CASE WHEN pr.status = 'OPEN' THEN pr.id END) as open_ports,
    COUNT(DISTINCT nd.id) as devices_found,
    COUNT(DISTINCT v.id) as vulnerabilities_found
FROM scans s
LEFT JOIN port_results pr ON s.id = pr.scan_id
LEFT JOIN network_devices nd ON s.id = nd.scan_id
LEFT JOIN vulnerabilities v ON s.id = v.scan_id
GROUP BY s.id, s.scan_date, s.target_ip, s.scan_type, s.duration_seconds
ORDER BY s.scan_date DESC;
GO

PRINT 'Vista v_latest_scans creada';
GO

-- Vista: puertos abiertos críticos
IF EXISTS (SELECT * FROM sys.views WHERE name = 'v_critical_open_ports')
    DROP VIEW v_critical_open_ports;
GO

CREATE VIEW v_critical_open_ports AS
SELECT 
    pr.port,
    pr.service,
    s.target_ip,
    pr.detected_date,
    s.scan_type
FROM port_results pr
INNER JOIN scans s ON pr.scan_id = s.id
WHERE pr.status = 'OPEN'
  AND pr.port IN (21, 23, 3389, 5900, 445)  -- Puertos críticos
ORDER BY pr.detected_date DESC;
GO

PRINT 'Vista v_critical_open_ports creada';
GO

-- ============================================
-- Procedimientos almacenados
-- ============================================

-- Procedimiento: Insertar escaneo nuevo
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_create_scan')
    DROP PROCEDURE sp_create_scan;
GO

CREATE PROCEDURE sp_create_scan
    @target_ip VARCHAR(15),
    @scan_type VARCHAR(50),
    @target_network VARCHAR(20) = NULL,
    @notes TEXT = NULL,
    @scan_id INT OUTPUT
AS
BEGIN
    INSERT INTO scans (target_ip, scan_type, target_network, notes)
    VALUES (@target_ip, @scan_type, @target_network, @notes);
    
    SET @scan_id = SCOPE_IDENTITY();
    
    SELECT @scan_id as scan_id, 'Scan created successfully' as message;
END
GO

PRINT 'Procedimiento sp_create_scan creado';
GO

-- Procedimiento: Obtener estadísticas
IF EXISTS (SELECT * FROM sys.procedures WHERE name = 'sp_get_scan_statistics')
    DROP PROCEDURE sp_get_scan_statistics;
GO

CREATE PROCEDURE sp_get_scan_statistics
    @days INT = 7
AS
BEGIN
    DECLARE @date_from DATETIME;
    SET @date_from = DATEADD(day, -@days, GETDATE());
    
    -- Estadísticas generales
    SELECT 
        COUNT(DISTINCT s.id) as total_scans,
        COUNT(DISTINCT CASE WHEN pr.status = 'OPEN' THEN pr.id END) as total_open_ports,
        COUNT(DISTINCT nd.id) as total_devices,
        COUNT(DISTINCT v.id) as total_vulnerabilities,
        COUNT(DISTINCT CASE WHEN v.severity = 'CRITICAL' THEN v.id END) as critical_vulnerabilities
    FROM scans s
    LEFT JOIN port_results pr ON s.id = pr.scan_id
    LEFT JOIN network_devices nd ON s.id = nd.scan_id
    LEFT JOIN vulnerabilities v ON s.id = v.scan_id
    WHERE s.scan_date >= @date_from;
END
GO

PRINT 'Procedimiento sp_get_scan_statistics creado';
GO

-- ============================================
-- Insertar datos de ejemplo (opcional)
-- ============================================
PRINT '';
PRINT 'Base de datos configurada exitosamente';
PRINT 'Tablas creadas: scans, port_results, network_devices, vulnerabilities';
PRINT 'Vistas creadas: v_latest_scans, v_critical_open_ports';
PRINT 'Procedimientos creados: sp_create_scan, sp_get_scan_statistics';
PRINT '';
PRINT '¡Listo para usar!';
GO
