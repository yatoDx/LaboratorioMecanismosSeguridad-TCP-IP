# Laboratorio de Monitoreo de Seguridad de Red (TCP/IP)

Este repositorio contiene los scripts de configuración, plantillas de servicios, scripts de verificación, evidencias y el informe final del montaje de un laboratorio de red aislado para análisis de tráfico y monitoreo de seguridad.

---

## 📋 Resumen del Entorno

- **Caso:** C0
- **Hipervisor:** VirtualBox en Host Windows (Analista)
- **Modo de red:** Solo-anfitrión (*Host-Only*), red `192.168.50.0/24`, sin salida externa.
- **Máquinas Virtuales:** Ubuntu Server 24.04 LTS (x86_64)

### Topología y Direccionamiento

| Equipo / VM | IP | Rol y Servicios Principales |
|-------------|----|------------------------------|
| **gateway** | `192.168.50.1` | Router perimetral, firewall `nftables`, servidor de tiempo `chrony` (NTP stratum 10) |
| **analista** (host) | `192.168.50.10` | Estación de captura y análisis (Wireshark 4.6.9, Npcap) |
| **web** | `192.168.50.20` | Servidor HTTP `nginx` |
| **xmpp** | `192.168.50.30` | Servidor de mensajería `prosody` (XMPP en 5222/tcp) |
| **dns** | `192.168.50.53` | Servidor DNS local `dnsmasq` con zona `lab.internal` |

---

## 📁 Estructura del Repositorio

- **`config/`**: Archivos de configuración para las VMs (`netplan`, `dnsmasq`, `nftables`, `chrony`, `sysctl`).
- **`evidencia/`**:
  - Salidas de comandos de verificación (`config-*.txt`, `verificacion-*.txt`).
  - Pantallazos de comprobación de servicios y captura de tráfico (`pantallazos/`).
  - Scripts de captura de evidencias en PowerShell y Bash.
- **`configurar_rol.sh`**: Script para aprovisionar y configurar roles en las VMs Ubuntu.
- **`verificar_laboratorio.ps1` / `verificar_laboratorio.sh`**: Scripts de pruebas cruzadas de conectividad, resolución DNS, firewall y servicios.
- **`hash_evidencia.py`**: Generador de hashes criptográficos (SHA-256, SHA-1, MD5) para trazabilidad de evidencias.
- **`evidencia.log`**: Registro de hashes e integridad de las evidencias.
- **`informe-laboratorio.md`**: Informe técnico completo y detallado del laboratorio.
- **`fichas/`, `scripts/`, `evidencia/casos/`, `entrega-parte-i/`**: Parte I (10 casos de análisis): fichas, generadores y analizadores, evidencia y paquete de entrega con manifiesto SHA-256.
- **`parte2/`**: Parte II, sistema de localización con consentimiento (API FastAPI + interfaz web con mapa). Ver [`parte2/README.md`](parte2/README.md).
- **`ejecutar_pruebas.sh`**: Ejecuta las pruebas de la Parte I (34) y de la Parte II (61).
- **Credenciales:** `vmctl.py` y `evidencia/capturar_pantallazos.sh` leen `LAB_USER` (por defecto `lab`) y `LAB_PASS` del entorno.

---

## 📄 Informe Técnico Completo

Consulte el archivo [informe-laboratorio.md](informe-laboratorio.md) para ver la documentación exhaustiva con resultados, diagramas de flujo, políticas de firewall y matriz de conectividad.

