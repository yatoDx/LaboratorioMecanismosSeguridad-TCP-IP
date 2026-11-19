# Diseño de seguridad y límites (Parte II)

## Riesgo principal: uso como herramienta de acecho
Un localizador puede usarse contra alguien sin que lo sepa. Mitigaciones implementadas:

| Riesgo | Control |
|---|---|
| Seguimiento encubierto | Uso compartido apagado por defecto; banner permanente; el observador solo ve tras aprobación explícita del dueño |
| Permiso indefinido | Cada permiso vence (1–90 días); el vencimiento se aplica en cada consulta |
| No poder retirar el permiso | Revocación inmediata; el observador pierde acceso en la siguiente petición |
| Consultas ocultas | Registro de actividad visible para el dueño (quién pidió, aprobó, consultó) |
| Insistencia / hostigamiento | 5 solicitudes/día por observador; 24 h de espera tras un rechazo |
| Averiguar quién usa el sistema | Respuestas idénticas exista o no el número; sin enumeración de teléfonos |
| Datos que se acumulan | Retención de 30 días; "borrar mi historial" y "eliminar mi cuenta" |

## Autenticación y tokens
Código de 6 dígitos con `secrets`, guardado solo como HMAC-SHA256; 5 intentos, vigencia 600 s, 3 códigos/10 min por teléfono y 20/h por IP. Tokens de sesión (`token_urlsafe(32)`) guardados como SHA-256; sesión de dispositivo 720 h, de observador 12 h; una sesión activa por dispositivo.

## Aplicación web
CSP restrictiva, `nosniff`, `no-referrer`, `Permissions-Policy`, `Cache-Control: no-store` en `/api`; la interfaz no usa `innerHTML` (todo con `textContent`); Leaflet incluido localmente (sin CDN); errores de validación sin eco de la entrada.

## Límites honestos
- Es una **aplicación web/PWA**, no una app nativa Android/iOS; el GPS en segundo plano y el ahorro de batería no se implementaron (un navegador no garantiza envíos con la pantalla bloqueada).
- El **SMS está simulado** (consola/memoria); el proveedor real solo tiene la interfaz.
- **Bot de Telegram** (opcional en la guía): no implementado. WhatsApp: no viable de forma directa.
- Base de datos **SQLite** por defecto; PostgreSQL por URL, sin probar. MongoDB y Firebase no se usaron.
- Geocodificación inversa desactivada por defecto (necesita red y respetar la política de uso de Nominatim).
- Los mosaicos de OpenStreetMap requieren Internet; en el laboratorio aislado el mapa se ve sin fondo.
- Hace falta **HTTPS** en un despliegue real (la geolocalización del navegador lo exige fuera de localhost).
- No hay multidispositivo por usuario ni verificación de propiedad del SIM más allá del código SMS.
- Prueba de seguridad propia (pruebas automáticas); no hubo auditoría independiente.
