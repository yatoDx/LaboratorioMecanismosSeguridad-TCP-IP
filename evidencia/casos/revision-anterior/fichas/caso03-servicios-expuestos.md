# Ficha de hallazgo — CASO-03: Servicios expuestos

## Los 9 campos

1. **ID del caso:** `CASO-03`
2. **Título:** Inventario y exposición de servicios en escucha
3. **Fecha y analista:** 2026-11-18 · Analista (host Windows, 192.168.50.10)
4. **Categoría / técnica:** Reconocimiento / endurecimiento (hardening) · Capas 4–7
5. **Descripción del hallazgo:** inventario de sockets en escucha con
   `ss -tulpn` en las 4 VMs y `netstat -ano` en el host. Se identifican los
   servicios de infraestructura (SSH, NTP, DNS, HTTP, XMPP) y dos exposiciones
   a revisar: el puerto **5269 (XMPP s2s)** abierto en `0.0.0.0` y el **SSH**
   abierto en `0.0.0.0` en las cuatro VMs (mitigado por el firewall del gateway).
6. **Severidad:** **Media** — sin salida a Internet y con firewall perimetral,
   el impacto queda contenido; los hallazgos son de endurecimiento.
7. **Evidencia asociada:**
   - `evidencia/casos/caso03-ss-tulpn.txt`
   - `evidencia/casos/caso03-auth-events.txt`
   - `evidencia/casos/caso03-netstat-host.txt`
   - `evidencia/casos/caso03-riesgo.png` (matriz riesgo/criticidad)
8. **Observables (IoC):**
   - `0.0.0.0:5269` y `[::]:5269` en xmpp (prosody s2s)
   - `0.0.0.0:22` en gateway, web, dns, xmpp
   - `0.0.0.0:80` en web; `192.168.50.53:53` en dns (bind-interfaces correcto)
   - Eventos de autenticación: solo `Accepted password for lab` desde
     `192.168.50.10`; sin `Failed password`.
9. **Clasificación / estado:** Hallazgo de configuración (no intrusión).

## Indicadores

- 4 VMs exponen SSH (22/tcp) en todas las interfaces.
- xmpp expone s2s (5269/tcp) sin necesidad en un laboratorio aislado.
- nginx sirve HTTP (80/tcp) sin TLS.
- dnsmasq escucha únicamente en `192.168.50.53` (correcto, `bind-interfaces`).
- El host Windows tiene su conjunto propio de sockets (ver `netstat -ano`).

## Análisis

| VM | Puerto | Servicio | Escucha | Riesgo | Observación |
|----|--------|----------|---------|--------|-------------|
| gateway | 22/tcp | sshd | 0.0.0.0 | Bajo | limitado por nftables a 192.168.50.0/24 |
| gateway | 123/udp | chronyd | 0.0.0.0 | Bajo | NTP del laboratorio |
| gateway | 53 | systemd-resolve | loopback | Nulo | interno del sistema |
| web | 80/tcp | nginx | 0.0.0.0 | Medio | sin TLS (claro) |
| web | 22/tcp | sshd | 0.0.0.0 | Bajo | limitado por nftables |
| dns | 53 | dnsmasq | 192.168.50.53 | Bajo | `bind-interfaces` correcto |
| dns | 22/tcp | sshd | 0.0.0.0 | Bajo | limitado por nftables |
| xmpp | 5222/tcp | prosody c2s | 0.0.0.0 | Bajo | cliente-servidor del lab |
| xmpp | **5269/tcp** | prosody s2s | 0.0.0.0 | **Medio** | federación no requerida |
| xmpp | 22/tcp | sshd | 0.0.0.0 | Bajo | limitado por nftables |

## Controles / mitigación (plan de remediación)

1. **Deshabilitar s2s** en prosody (`xmpp`: `s2s_ports = {}` o firewall) para
   cerrar 5269, innecesario sin federación.
2. **Vincular sshd** a la IP del laboratorio (`ListenAddress 192.168.50.x`) en
   cada VM como defensa en profundidad (ya existe el límite en nftables).
3. **Evaluar TLS** en nginx si el web llegara a transportar datos sensibles.
4. **Confirmar** que dnsmasq mantiene `bind-interfaces` y `no-resolv` (sin
   upstream), evitando convertirse en resolvedor abierto.
5. **Auditoría de autenticación:** conservar el registro de `Accepted/Failed
   password` y alertar ante intentos fallidos repetidos.

## Preguntas de análisis

1. *¿Qué servicio representa la mayor exposición real?* — El s2s de prosody
   (5269), porque está abierto sin una necesidad funcional en el laboratorio.
2. *¿Por qué el SSH en 0.0.0.0 no es crítico aquí?* — Porque el firewall del
   gateway solo permite SSH desde 192.168.50.0/24 y la red no tiene salida.
3. *¿Qué confirma el inventario sobre dnsmasq?* — Que escucha solo en
   192.168.50.53, evitando el riesgo de resolvedor abierto.

## Regla de detección

Regla nftables para cerrar el s2s de prosody (control correctivo):

```nft
# Bloquear federación XMPP (5269) en el gateway
ip daddr 192.168.50.30 tcp dport 5269 drop
```
