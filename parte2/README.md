# Parte II — Sistema de localización con consentimiento

Aplicación web (PWA) + API REST para compartir la ubicación de un teléfono **solo con permiso expreso, limitado en el tiempo y revocable**. Proyecto académico (Taller 2, Mecanismos de Seguridad).

## Ejecutar

```bash
cd parte2
pip install -r requirements.txt
LOC_DEV_SHOW_CODE=1 uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000
# abrir http://127.0.0.1:8000
```

`LOC_DEV_SHOW_CODE=1` muestra en pantalla el código SMS (solo para demostración; sin proveedor real de SMS el código también sale por la consola del servidor).

## Pruebas

```bash
python -m pytest -q                      # 61 pruebas de API (autenticación, consentimiento, ubicaciones)
python tests/e2e_navegador.py            # flujo completo en Chrome con dos personas (genera docs/capturas/)
```

## Variables de entorno

| Variable | Defecto | Uso |
|---|---|---|
| `LOC_DATABASE_URL` | `sqlite:///./parte2.db` | Base de datos (SQLAlchemy; otra URL, p. ej. PostgreSQL, es posible pero **no se probó**) |
| `LOC_SECRET` | aleatorio por proceso | Clave HMAC de los códigos; fíjela en producción |
| `LOC_RETENTION_DAYS` | 30 | Retención del historial (`python -m app.maintenance` purga) |
| `LOC_REQUESTS_PER_DAY` | 5 | Solicitudes de permiso por observador y día |
| `LOC_SMS_BACKEND` | `console` | `console` o `memory`; un proveedor real exige implementar `SmsBackend` |
| `LOC_GEOCODER_URL` | vacío (desactivado) | Geocodificación inversa (Nominatim); requiere red |

## Flujo

1. **Registro**: número de teléfono → código de 6 dígitos por SMS → sesión con token.
2. **Dueño del teléfono**: el uso compartido nace **apagado**. Un banner permanente indica si se comparte o no.
3. **Observador**: pide permiso con un mensaje. No ve nada hasta que el dueño aprueba (1–90 días, con o sin historial).
4. **Ubicación**: GPS del navegador (periódico, por defecto 10 min) o envío manual.
5. **Mapa** (Leaflet/OpenStreetMap): última posición, recorrido por fecha, estadísticas, zonas (geocercas) con alertas de entrada/salida.
6. **Control**: el dueño revoca en cualquier momento (efecto inmediato), ve un registro de quién consultó, borra su historial o su cuenta.

## API (resumen)

`POST /api/auth/request-code`, `/api/auth/verify`, `/api/auth/logout`, `GET|DELETE /api/me` ·
Dispositivo: `GET /api/device/status`, `PUT /api/device/sharing`, `POST|DELETE /api/device/locations`, `POST /api/device/grants/{id}/approve|deny|revoke`, `GET /api/device/audit` ·
Observador: `POST /api/viewer/requests`, `GET /api/viewer/grants`, `GET /api/viewer/grants/{id}/latest|history|stats|geofences|alerts`, `POST|DELETE …/geofences`, `GET /api/viewer/geocode`.
Documentación interactiva en `/docs` de FastAPI.

Más detalle de seguridad y límites: [`docs/seguridad-y-limites.md`](docs/seguridad-y-limites.md). Capturas: [`docs/capturas/`](docs/capturas/).
