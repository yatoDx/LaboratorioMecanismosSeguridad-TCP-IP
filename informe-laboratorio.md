# Informe final — Laboratorio de monitoreo de seguridad de red

**Alcance:** laboratorio C0 + Parte I (casos 01–10) · **Fecha local:** 2026-11-18 · **Entorno:** VirtualBox (Windows) · **Red de laboratorio:** 192.168.50.0/24

**Entrega técnica:** fichas, análisis, reglas propuestas, PCAP/logs y pantallazos reales. La Parte II no se incluye; la aceptación docente, el formato literal del apartado 7 y la validación humana del Caso 09 siguen pendientes.

---

## 1. Objetivo

Montar un laboratorio de red aislado para el análisis de tráfico y monitoreo de
seguridad, compuesto por cuatro máquinas virtuales Ubuntu Server y un equipo
analista (host Windows) con herramientas de captura y análisis. El laboratorio
opera en modo **solo-anfitrión (host-only)**, con las VMs sin NAT ni ruta por
defecto, servicios NTP/DNS/web/XMPP y firewall local en el gateway. Los peers
comparten subred: el gateway no está en su camino de tráfico y no los protege
como firewall perimetral. El host Windows mantiene otras interfaces; no se
certifica su aislamiento total.

La Parte I analiza diez casos mediante tráfico benigno real, PCAP sintéticos
escritos a archivo sin transmisión y registros sintéticos identificados.
Se distinguen observación, simulación y propuestas de mitigación; no se
realizaron ataques de disponibilidad, escaneos agresivos ni exfiltración.

---

## 2. Topología y direccionamiento

```
                        Red aislada 192.168.50.0/24 (solo-anfitrión)
        ┌────────────────────────────────────────────────────────────┐
        │                                                            │
   ┌────┴─────┐      ┌──────────┐   ┌──────────┐   ┌──────────┐     │
   │ gateway  │      │   web    │   │   dns    │   │   xmpp   │     │
   │  .1      │      │  .20     │   │  .53     │   │  .30     │     │
   │ chrony   │      │ nginx    │   │ dnsmasq  │   │ prosody  │     │
   │ nftables │      │ :80      │   │ :53      │   │ :5222    │     │
   └────┬─────┘      └────┬─────┘   └────┬─────┘   └────┬─────┘     │
        │                 │              │               │           │
        └─────────────────┴──────────────┴───────────────┘           │
                                 │                                   │
                          ┌──────┴──────┐                            │
                          │  analista   │  host Windows              │
                          │   .10       │  Wireshark + Python        │
                          └─────────────┘                            │
        └────────────────────────────────────────────────────────────┘
```

| Rol | VM | IP | Servicio(s) |
|-----|----|----|-------------|
| gateway | lab-gateway | 192.168.50.1 | chrony (NTP), nftables |
| web | lab-web | 192.168.50.20 | nginx (HTTP :80) |
| dns | lab-dns | 192.168.50.53 | dnsmasq (DNS :53) |
| xmpp | lab-xmpp | 192.168.50.30 | prosody (XMPP c2s :5222) |
| analista | host Windows | 192.168.50.10 | Wireshark, Python 3 |

**Estado final de red (post-aislamiento):** cada VM tiene un único adaptador
habilitado:

- **Adaptador 1 (NAT):** deshabilitado (`--nic1 none`). Se usó únicamente durante
  la instalación para descargar paquetes y se retiró al completar el laboratorio.
  Esta evidencia elimina la salida NAT configurada, no demuestra ausencia de
  cualquier vía indirecta a través del anfitrión.
- **Adaptador 2 (solo-anfitrión, enp0s8):** IP estática en 192.168.50.0/24, es la
  red operativa del laboratorio. Es la única interfaz presente (`ip -br addr`
  muestra solo `lo` y `enp0s8`) y no existe ruta por defecto (`ip route` muestra
  únicamente `192.168.50.0/24 dev enp0s8`).

El netplan se dejó limpio: `/etc/netplan/01-lab.yaml` conserva solo el bloque de
`enp0s8` con la IP estática del rol.

---

## 3. Inventario de software

### Plataforma de virtualización
- VirtualBox **7.2.22** (r175245).

### Máquinas virtuales (4 × 1 vCPU / 1 GB RAM)
- Ubuntu Server **24.04.5 LTS**, kernel **6.8.0-149-generic**.

| Componente | Versión |
|------------|---------|
| chrony | 4.5-1ubuntu4.2 |
| nftables | (nativo del kernel) |
| nginx | 1.24.0 |
| dnsmasq | 2.91 |
| prosody | 0.12.4 |

### Host analista (Windows)
| Herramienta | Versión |
|-------------|---------|
| Wireshark | 4.6.9 |
| Npcap | 1.90 |
| Python | 3.14.7 |
| scikit-learn | 1.9.1 |
| pandas | 3.1.1 |
| matplotlib | 3.11.2 |

---

## 4. Configuración por rol

### 4.1 Gateway (192.168.50.1)

- **Zona horaria:** `America/Bogota`.
- **NTP:** chrony sirve hora al laboratorio (`allow 192.168.50.0/24`,
  `local stratum 10`), escuchando en el puerto 123.
- **Reenvío deshabilitado:** `net.ipv4.ip_forward = 0`.
- **Firewall (nftables):**

```
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ip saddr 192.168.50.0/24 icmp type echo-request accept
    ip saddr 192.168.50.0/24 udp dport 123 accept
    ip saddr 192.168.50.0/24 tcp dport 22 accept
  }
  chain forward { type filter hook forward priority 0; policy drop; }
}
```

### 4.2 Web (192.168.50.20)

- nginx activo y escuchando en el puerto 80. Responde `HTTP/1.1 200 OK` en
  `http://192.168.50.20/`.

### 4.3 DNS (192.168.50.53)

- dnsmasq escuchando en el puerto 53 (UDP/TCP), configuración
  (`/etc/dnsmasq.d/lab.conf`):

```
listen-address=192.168.50.53
bind-interfaces
no-resolv
address=/web.lab.local/192.168.50.20
```

- Resolución verificada: `web.lab.local → 192.168.50.20`.
- Durante Parte I se habilitó el registro de consultas (`log-queries`); los
  fragmentos exportados están en las evidencias de casos 02, 06 y 09. Consultas
  de aplicaciones del anfitrión a dominios externos recibieron REFUSED; no son
  prueba de exfiltración ni de salida a Internet desde las VMs.

### 4.4 XMPP (192.168.50.30)

- Prosody activo, escuchando en 5222 (c2s) y 5269 (s2s).
- Caso 10 añadió `VirtualHost "xmpp.lab.local"`, certificado autofirmado con
  SAN correcto y 30 días de vigencia, STARTTLS requerido y autenticación PLAIN
  sin cifrado deshabilitada. El certificado público se exportó, no la clave.
- Se verificó TLS 1.3 con `TLS_AES_256_GCM_SHA384`, confianza explícita por
  invocación OpenSSL y rechazo sin confianza o con nombre incorrecto.
- `prosodyctl check certs` global sigue fallando por localhost sin certificado
  y advierte de la corta vigencia. No se probaron login real ni federación.
  Detalles y pantallazos en [ficha 10](fichas/caso10-xmpp-tls.md).

### 4.5 Analista (192.168.50.10)

- Adaptador solo-anfitrión con IP estática 192.168.50.10/24 y DNS 192.168.50.53.
- Regla de firewall de Windows que permite ICMP entrante desde 192.168.50.0/24
  (`Lab-ICMPv4-Echo-In-192.168.50.0-24`, Inbound, Allow).
- Wireshark + Npcap instalados; captura en vivo sobre el adaptador
  "Ethernet 2" verificada.

---

## 5. Seguridad de red

- **Aislamiento de las VMs:** NAT deshabilitado (`--nic1 none`), sin ruta por
  defecto y solo adaptador host-only. El ping sin respuesta a `192.0.2.1` es
  un indicio auxiliar, no una prueba suficiente por sí solo; es TEST-NET y puede
  no responder también en una red conectada.
- **Firewall local del gateway:** política `drop` en `input` y `forward`;
  acepta loopback, tráfico establecido/relacionado y gestión ICMP/NTP/SSH
  desde la red de laboratorio. No filtra comunicaciones directas entre los
  peers de 192.168.50.0/24. Las reglas propuestas de Parte I deben ubicarse
  en el equipo protegido o en un punto de tránsito real, no asumir que basta
  instalarlas en este gateway.
- **Sin reenvío de paquetes:** `ip_forward = 0` (el gateway no enruta).
- **Identidades SSH únicas:** las claves de host SSH se regeneraron en las VMs
  clonadas, de modo que cada VM tiene una huella distinta.

---

## 6. Sincronización de tiempo (NTP)

- El gateway actúa como servidor NTP del laboratorio (chrony, `local stratum 10`),
  escuchando en el puerto 123 y aceptando clientes de `192.168.50.0/24`.
- Los clientes (web, dns, xmpp) sincronizan contra el gateway mediante **chrony**
  (`server 192.168.50.1 iburst` en `/etc/chrony/chrony.conf`). `chronyc sources`
  muestra la fuente `^* 192.168.50.1` y `chronyc tracking` reporta
  `Reference ID : C0A83201 (192.168.50.1)`.
- El equipo analista (Windows) sincroniza con el gateway mediante el servicio de
  hora de Windows (w32time), configurado con `manualpeerlist=192.168.50.1`;
  `w32tm /query /status` reporta `Origen: 192.168.50.1` (capa 4).
- Estado verificado en todas las VMs: `System clock synchronized: yes`,
  zona horaria `America/Bogota`.

> Nota: las VMs usan **chrony** (heredado de la plantilla del gateway), no
> `systemd-timesyncd`; por eso la evidencia de sincronización de los clientes se
> obtiene con `chronyc sources`/`chronyc tracking` en lugar de
> `timedatectl timesync-status`.

---

## 7. Verificación

Se ejecutó `verificar_laboratorio.sh <rol>` en las cuatro VMs (antes y después
de retirar el NAT) y `verificar_laboratorio.ps1 -Rol analista` en el host.
Los verificadores C0 informaron conectividad de la malla y servicios activos
por rol (chrony/NTP, nftables, nginx, dnsmasq, prosody), con la advertencia del
PATH de Wireshark indicada abajo. Sus `[OK]` describen esas comprobaciones,
no una auditoría integral de seguridad ni una verificación de TLS: el Caso 10
detectó posteriormente la falta de certificado. El aislamiento de las VMs
se sustenta en adaptadores y rutas, con los límites de la sección 5.

### Verificación posterior al aislamiento (sin NAT)

| VM | IP | Servicio verificado |
|----|----|---------------------|
| gateway | .1 | chrony (123), nftables, ip_forward=0 |
| web | .20 | nginx (80), HTTP 200 OK |
| dns | .53 | dnsmasq (53), web.lab.local → .20 |
| xmpp | .30 | prosody (5222) |

### Verificación del analista (host Windows)

`verificar_laboratorio.ps1 -Rol analista`: **11 OK | 0 FALTA | 1 advertencia**
(Wireshark no está en el `PATH`, pero sí instalado; ver sección 3).

| Chequeo | Resultado |
|---------|-----------|
| IP 192.168.50.10 en "Ethernet 2" | [OK] |
| DNS 192.168.50.53 configurado | [OK] |
| Ping a gateway / web / dns / xmpp | [OK] × 4 |
| Aislamiento (192.0.2.1 no responde) | [OK] |
| TCP 80 (HTTP), 53 (DNS), 5222 (XMPP) abiertos | [OK] × 3 |
| Wireshark detectado | [?] (fuera del PATH) |
| Python 3.14.7 | [OK] |

---

## 8. Evidencia forense

Los artefactos se encuentran en `evidencia/` y sus resúmenes criptográficos en
`evidencia.log` (rutas relativas a `lab`). SHA-256 es la referencia de integridad;
SHA-1 y MD5 solo se conservan como datos auxiliares del script existente.

**C0 histórico:** las tablas siguientes conservan los valores originales. Las
inconsistencias de hashes y el README desactualizado se dejan tal como estaban,
según la decisión del grupo; no se reescriben como si fueran evidencia validada.
Los snapshots son del laboratorio base, anteriores a los cambios DNS/TLS de
Parte I, y no contienen necesariamente esos cambios.

**Cierre de Parte I:** `entrega-parte-i/` conserva `original/` y `trabajo/` con
la misma estructura y bytes verificados, además de `manifiesto-sha256.json` y
su huella en `manifiesto-sha256.txt`. Se preservan las revisiones anteriores en
sus subdirectorios y se distinguen de los resultados vigentes. «Original»
designa la copia maestra hecha al cierre, no una adquisición inmutable desde
el inicio: el taller ya había generado y revisado artefactos antes de copiarla.
No se impusieron ACL ni almacenamiento WORM; no editar la copia maestra.

`hash_evidencia.py` registra los archivos finales en un log de cierre y anexa
el mismo bloque a `evidencia.log`, sin borrar registros históricos. El manifiesto
incluye ambos logs sin intentar que un archivo contenga su propio hash.
Revisar las copias con `python scripts/cerrar_parte_i.py --verificar`; el hash
detecta cambios respecto del cierre, no certifica veracidad ni autoría.
Los scripts que acceden a VMs dependen del helper `vmctl.py`, que no se incluye
en el paquete de entrega. Desde la corrección de entrega lee la contraseña de la
variable de entorno `LAB_PASS`; versiones anteriores del historial de Git la
contenían en claro, por lo que debe considerarse expuesta y cambiarse en las VMs
si el laboratorio se reutiliza fuera de la red aislada.

### Capturas de texto

| Archivo | SHA-256 |
|---------|---------|
| verificacion-gateway.txt | `389c3189ada8cd32cfd7fc2220ca594ee006ae5aa35018061b06ef88661ce8bf` |
| verificacion-web.txt | `e77c8b08c586b2ecea304458f1115498bfb7d1fd039db698b083a9a3e73f2eb6` |
| verificacion-dns.txt | `8cc8a414f1ac9944148d2d7ba3704e017b4e870da3d2da014909876b41f0fe48` |
| verificacion-xmpp.txt | `22746f6daa1df58e0680728f6d8a843d640bc7a1182cb0daf65225f4a4e8899b` |
| config-gateway.txt | `587fb41aeba65ea5156ee1c3767624ca4c445dc03bcb84160360879d614abcf2` |
| config-web.txt | `64d8876a874c6de64d49917c8044be7aa9c061a72925c3e85ab10c9fe4a1fe4a` |
| config-dns.txt | `996bbfcdd3d1269f1575d9bf439e861645a0ef12f2f4a36343e8976525343158` |
| config-xmpp.txt | `68bb31dd143f9b507173b334c1a7e23c58d0c39480b1b3abb1b13574ad947e97` |
| config-host.txt | `a76c2cbc84772eeabec41611b9bf10af7d2384662f07e0729889e6e203c1cd17` |
| wireshark-version.txt | `d62e5610c4ce1bf6f9d3c1047c7023152f19d6a11920272077cc0830fbfd8433` |

### Capturas de pantalla (PNG)

| Archivo | Contenido | SHA-256 |
|---------|-----------|---------|
| gateway-firewall.png | nftables + ip_forward=0 | `f69c81637db7d3700cbf7c39eeaa96bff4923f0f84234b04f99e40a257541cc2` |
| web-nginx.png | IP, nginx active, HTTP 200 | `a0db955414fc1178247bfe44bbdc4ba852c49c24b5403e1b5feefb5030b1d063` |
| dns-resolucion.png | dig web.lab.local → .20 | `2187a183d6a7a5e76b5f6e45f1cdc6fc6e9fc50e29685ea171c258953e338b06` |
| xmpp-prosody.png | prosody active, :5222 | `86a96a0a62f82a995827e787648a1761c80590d19ad892e2d253f79b95788904` |
| host-wireshark.png | captura en vivo (ICMP/HTTP/DNS/ARP) | `82455f8af4cb0ee86c4437e5c2e14546dc8f18d1f332f9f97c2b43b90583d5ab` |

### Evidencia del analista (A.2)

| Archivo | Contenido | SHA-256 |
|---------|-----------|---------|
| analista-w32tm.txt | w32tm /query /status + /peers (Origen 192.168.50.1) | `010855ffff8e01f3b1d775fb8ca69871e7f8c8218a0d1cd6d7a109ad576dad1c` |
| analista-timesync-cliente.txt | chronyc sources/tracking + timedatectl en web | `2b73b0cb6a428f12aa65436670d79f5f937692a1f609bde5022a725eddde6574` |
| verificacion-analista.txt | verificar_laboratorio.ps1 -Rol analista (11 OK) | `a7eebfd6287d3eb99dd156aad70c3aa3785be86205129d6eb84b3a9c5ce40c0d` |
| host-w32tm.png | consola Windows con w32tm → 192.168.50.1 | `d5052c17ef25476318ce7083573d4c0ca8bb0555772e9338244d75dd2127d306` |
| web-ntp.png | chronyc sources/tracking en web (^* 192.168.50.1) | `1602e51ff64a67c91dec466246b1beff2ad60dfefbeb6ff644d8787b57135231` |
| host-verificacion-analista.png | verificar_laboratorio.ps1 -Rol analista | `57b6d9c00abce6b51db3e3b4057286a2b5ef9d424d4b87aab8da08ba9b79ca6d` |

### Verificación post-aislamiento, sin NAT (A.1)

| Archivo | Contenido | SHA-256 |
|---------|-----------|---------|
| verificacion-aislado-gateway.txt | gateway: solo enp0s8, nftables, ip_forward=0 | `99c3ca40a03f97ad37eb46ba00324c4f730d99944fd03aadeea667447133ef08` |
| verificacion-aislado-web.txt | web: solo enp0s8, nginx/HTTP OK | `5873537a56d71a1ed704b940d179594002fdd1d96b53b1e82123534594dcec25` |
| verificacion-aislado-dns.txt | dns: solo enp0s8, dnsmasq, web.lab.local → .20 | `af4f884b3824e5af8accbcca9957393a88842798dc875536b92e4dfde6a510dd` |
| verificacion-aislado-xmpp.txt | xmpp: solo enp0s8, prosody :5222 | `4b0829267b99e9f6b475f8b7d1b5e930c9d6278de3b64cf37984ad99d9e8335b` |
| gateway-aislado.png | ip -br addr (solo enp0s8) + ip route + nftables | `56b3877d1ad2e7607604bfd57f9940efd9423aaa42cd7be10290b6a9db84b9b1` |

### Tráfico de línea base (A.3)

| Archivo | Contenido | SHA-256 |
|---------|-----------|---------|
| baseline-normal.pcapng | 5 min de tráfico normal en "Ethernet 2" (ping 4 VMs, HTTP, DNS) | `301ea4766c642919734e3649b1de4c049bb4bebeb8ff9b4125306322b3b076ff` |

### Snapshots de VirtualBox

Snapshot `lab-base-aislado` tomado en las cuatro VMs:

| VM | UUID |
|----|------|
| lab-gateway | `ca2594b3-1ae3-4645-ae2f-bd470c40d7fd` |
| lab-web | `e10550ab-4905-4e6d-b095-00233fc459ac` |
| lab-dns | `55768ab5-9fdc-4c80-ae9f-28191827db78` |
| lab-xmpp | `bfe946eb-9790-430d-aefd-db6de7a6a736` |

Snapshot `lab-base-aislado-v2` (post-NAT: solo host-only, netplan limpio, NTP
de clientes contra el gateway) tomado en las cuatro VMs:

| VM | UUID |
|----|------|
| lab-gateway | `01789e81-c078-4011-82bf-1d3852143156` |
| lab-web | `ffa916e9-6817-40d2-81bd-482c92d07aa3` |
| lab-dns | `19ff33ba-5028-48b7-a3a0-ec2e9fce187d` |
| lab-xmpp | `5e98c08c-d342-42bd-8657-f07656b9d238` |

---

## 9. Observaciones técnicas

- **Rutas "fantasma" del DHCP de VirtualBox NAT:** el servidor DHCP del adaptador
  NAT inyectaba rutas estáticas de clase (opción 121) hacia `192.168.50.53` y
  `192.168.0.1` vía `10.0.2.2`, lo que rompía el enrutamiento asimétrico entre
  la VM DNS y el resto del laboratorio. Solución permanente:
  `dhcp4-overrides: use-routes: false` en el netplan de las cuatro VMs.
- **Puerto 53 ocupado por systemd-resolved:** se añadió `bind-interfaces` a la
  configuración de dnsmasq para evitar el conflicto en 127.0.0.53.
- **ICMP del host bloqueado por Windows Firewall:** se creó una regla que permite
  echo ICMP entrante desde 192.168.50.0/24 para que el analista responda a ping.
- **Claves SSH duplicadas en clones:** regeneradas para que cada VM tenga una
  identidad única.
- **Npcap:** no venía incluido en la instalación de Wireshark; se instaló
  Npcap 1.90 (npcap.com) y se verificó captura sin privilegios de administrador.
- **Retirada del NAT:** tras verificar el laboratorio, se apagaron las VMs, se
  deshabilitó el adaptador 1 (`--nic1 none`) y se depuró el netplan para dejar
  únicamente `enp0s8`. Las VMs quedan sin salida NAT ni ruta por defecto;
  esto no desconecta las otras interfaces del anfitrión Windows.
- **NTP en los clientes:** las VMs heredaron `chrony` de la plantilla del gateway
  (no `systemd-timesyncd`). Se reconfiguró `/etc/chrony/chrony.conf` de web, dns
  y xmpp a `server 192.168.50.1 iburst`, eliminando los `pool` externos.
- **Hora del analista:** el servicio w32time de Windows estaba detenido; se
  configuró para sincronizar desde `192.168.50.1` y se arrancó
  (`w32tm /config /manualpeerlist:192.168.50.1 /syncfromflags:manual`).

---

## 10. Parte I — Diez casos y evidencias

Las fichas siguientes contienen nueve campos **provisionales**, método,
observables, reglas o criterios de detección, preguntas propuestas y límites.
No se dispuso del apartado 7 literal: no se afirma que su formato coincida con
los nueve campos oficiales. Las gráficas son resultados derivados; los PNG de
consola y Wireshark son pantallazos reales de programas, aunque visualicen
PCAP o registros sintéticos claramente rotulados.

| Caso y ficha | Datos y alcance | Resultado o cautela principal |
|---|---|---|
| [01 — SYN](fichas/caso01-syn-flood.md) | PCAP sintético offline y baseline real | Conteo de SYN iniciales y modelo de control; no se agotó ningún servidor |
| [02 — DNS](fichas/caso02-dns-tunneling.md) | PCAP sintético y consulta/log benigno independiente | Longitud de etiquetas y entropía; no se demostró exfiltración |
| [03 — Servicios expuestos](fichas/caso03-servicios-expuestos.md) | Inventario y salidas reales de servicios/sockets | Escucha local no equivale a accesibilidad desde cualquier red |
| [04 — Anomalías ML](fichas/caso04-anomalias-ml.md) | Baseline real + variantes tabulares sintéticas | 17 ventanas train, 1 embargo, 11 test normal; 22 variantes detectadas, con FP 1/11 en z-score y 5/11 en IsolationForest |
| [05 — RST TCP](fichas/caso05-rst-tcp.md) | PCAP didáctico offline | Interpretar tupla y secuencia; un RST fuera de flujo no demuestra interrupción |
| [06 — Reflexión UDP](fichas/caso06-reflexion-udp.md) | Representación sintética y comprobación DNS benigna | Medir tamaños y tasas; no se efectuó reflexión contra hosts |
| [07 — ICMP](fichas/caso07-icmp.md) | PCAP sintético y comparación con baseline | Distinguir tamaño de trama y payload, tasas y umbrales didácticos |
| [08 — Escaneo de puertos](fichas/caso08-escaneo-puertos.md) | PCAP sintético offline | Inferencias limitadas al escenario, no inventario real completo |
| [09 — Correlación SIEM](fichas/caso09-correlacion-siem.md) | 168 eventos reales + 21 sintéticos, separados | 37 ventanas; 0 alertas reales y 1 sintética de score 49; dictamen humano pendiente |
| [10 — XMPP/TLS](fichas/caso10-xmpp-tls.md) | Sesiones benignas, logs y PCAP reales | TLS 1.3 aceptado con confianza explícita; rechazos sin confianza y por nombre incorrecto |

### 10.1 Reglas y alcance de las mitigaciones

Los controles de SYN, DNS, UDP, ICMP y puertos se entregan como reglas o
criterios didácticos, con su estado de prueba en cada ficha. **No se aplicaron
reglas nuevas de filtrado a la infraestructura ni se probó resistencia a DoS.**
La reducción en una simulación offline no equivale a paquetes descartados por
el kernel ni demuestra disponibilidad bajo ataque. Los casos 05 y 08 no usan
Zeek ni Suricata.

El Caso 09 es un pipeline local de normalización y correlación, no una
instalación Wazuh ni un SIEM de producción. Agrupa por procedencia, origen y
minuto UTC; conserva fichero, línea y hash. El log nftables real está vacío
en el fragmento exportado: ese parser se ejercita con registros sintéticos.
No se atribuyen los DNS REFUSED sin origen a una IP de otra línea, no se
confunde desconexión con conexión y no se mezclan fuentes reales/simuladas.
No hubo bloqueos automáticos ni envío de logs a un LLM externo.

### 10.2 Evidencias visuales principales

Los pantallazos específicos de cada caso están enlazados en su ficha. Estos
muestran dos de los resultados verificables del cierre:

![SIEM local: eventos reales y sintéticos separados, revisión humana pendiente](evidencia/casos/caso09-consola-final.png)

![Wireshark: TLS 1.3 y dos controles negativos de certificado](evidencia/casos/caso10-wireshark.png)

### 10.3 Reproducción y preservación

Validación de cierre: **53 pruebas aprobadas** (27 de paquetes/controles,
19 de metodología ML y 7 de SIEM), más comprobación de las tres salidas TLS,
certificado y PCAP. Registro en `evidencia/casos/pruebas-cierre-parte-i.txt`.
La inspección visual confirmó pantallazos legibles; la comprobación de enlaces
verifica que las figuras de las diez fichas existen. Estos controles técnicos
no sustituyen la revisión humana pendiente.

1. Consultar la ficha y trabajar sobre una copia; no editar `original/`.
2. Ejecutar los analizadores y pruebas offline con las dependencias ya
   instaladas. Los generadores PCAP solo escriben archivos; no reproducirlos
   sobre la red. Mantener separados tiempos sintéticos y adquisición real.
3. Para TLS, usar la VM aprovisionada y el certificado público durante su
   vigencia, sin repetir `--provisionar`; la reproducción benigna y la captura
   de paquetes son operaciones separadas y generan nueva evidencia.
4. Verificar `entrega-parte-i/manifiesto-sha256.json` mediante el script de
   cierre en modo `--verificar`. Las revisiones históricas no son resultados
   vigentes; el log acumulado se preserva, no se edita retroactivamente.

## 11. Pendientes externos y trabajo posterior

| Pendiente | Responsable / acción requerida | Estado |
|---|---|---|
| A.4 — versiones y sustituto SIEM | Docente: aceptar herramientas y alcance del pipeline Python | Sin aprobación documentada |
| A.5 — fecha de entrega | Grupo/docente: resolver discrepancia entre 12 y 26 de octubre de 2026 | Sin confirmación |
| Apartado 7 literal | Grupo: aportar la guía y contrastar campos/preguntas oficiales | Fichas provisionales |
| Validación humana Caso 09 | Revisor: contrastar fuentes y completar nombre, fecha y dictamen en el registro, conservando la versión pendiente | PENDIENTE; no firmado automáticamente |
| Parte II | Diseñar sistema de ubicación con consentimiento, minimización y controles de acceso | Fuera de este cierre |
| Entrega global del taller | Grupo: incorporar aprobaciones y Parte II antes de declarar todo el taller terminado | No equivale al cierre técnico de Parte I |

Mejoras no ejecutadas: integrar Wireshark en PATH si el grupo lo desea,
completar gestión de certificados/localhost y evaluar autenticación/federación,
ampliar datos independientes de ML y calibrar umbrales. No se alteraron los
hashes históricos C0 ni el README por la decisión expresa del grupo.

## 12. Conclusión

La Parte I queda documentada con diez casos, evidencia real y sintética
identificada, pantallazos y copias verificables al cierre. Se corrigieron
inferencias que excedían los datos: ubicación del firewall, etiquetado y
separación de ML, atribución en correlación y validación TLS. Los resultados
son educativos y acotados; no certifican resistencia a ataques, aislamiento
total del anfitrión ni un detector listo para producción. La revisión humana,
la aceptación académica y la Parte II permanecen fuera de este cierre técnico.
