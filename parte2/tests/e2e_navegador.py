"""Prueba de extremo a extremo con un navegador real (Chrome) y dos personas.

Levanta el servidor, recorre el flujo completo de consentimiento y guarda
capturas en docs/capturas/. No es parte de `pytest` porque necesita Chrome:

    pip install playwright
    python tests/e2e_navegador.py [ruta/a/chrome]

Los mosaicos de OpenStreetMap necesitan Internet; en el laboratorio aislado no
cargan, así que el mapa se ve sin fondo (marcadores, recorrido y zonas sí).
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
SHOTS = ROOT / "docs" / "capturas"
PORT = 8765
BASE = f"http://127.0.0.1:{PORT}"
OWNER, WATCHER = "+573001112233", "+573004445566"
HOME = (4.5981, -74.0760)          # posición simulada del GPS del dueño
FAR = (4.6400, -74.0760)           # ~4,6 km al norte, fuera de la zona


def wait_server() -> None:
    import urllib.request
    for _ in range(60):
        try:
            urllib.request.urlopen(BASE + "/", timeout=1)
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("el servidor no arrancó")


def login(page, phone: str, role: str, label: str = "") -> None:
    page.goto(BASE + "/")
    page.fill("#phone", phone)
    page.select_option("#role", role)
    if label:
        page.fill("#label", label)
    page.click("#send")
    expect(page.locator("#devcode")).to_be_visible()


def main() -> None:
    chrome = sys.argv[1] if len(sys.argv) > 1 else "/usr/bin/google-chrome"
    SHOTS.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.mkdtemp()
    env = {**os.environ, "LOC_DATABASE_URL": f"sqlite:///{tmp}/e2e.db", "LOC_DEV_SHOW_CODE": "1",
           "LOC_MIN_POST_INTERVAL_S": "0", "LOC_SECRET": "e2e-" + "x" * 32}
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:create_app", "--factory", "--port", str(PORT),
                               "--log-level", "warning"], cwd=ROOT, env=env)
    try:
        wait_server()
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chrome, headless=True, args=["--no-sandbox"])
            # ---- dueño del teléfono: pantalla de móvil con GPS simulado
            ctx_o = browser.new_context(viewport={"width": 430, "height": 900}, geolocation={"latitude": HOME[0], "longitude": HOME[1], "accuracy": 18},
                                        permissions=["geolocation"], locale="es-CO", timezone_id="America/Bogota")
            owner = ctx_o.new_page()
            owner.on("pageerror", lambda e: print("ERROR JS (dueño):", e))
            # ---- observador: pantalla de escritorio
            ctx_w = browser.new_context(viewport={"width": 1180, "height": 980}, locale="es-CO", timezone_id="America/Bogota")
            watcher = ctx_w.new_page()
            watcher.on("pageerror", lambda e: print("ERROR JS (observador):", e))

            # 1-2. El dueño se registra por número y código
            login(owner, OWNER, "device", "Pixel 8")
            owner.screenshot(path=str(SHOTS / "01-registro-codigo.png"))
            owner.fill("#code", owner.inner_text("#devcode"))
            owner.click("#verify")
            expect(owner.locator("#banner")).to_contain_text("NO se está compartiendo")
            owner.screenshot(path=str(SHOTS / "02-dispositivo-apagado.png"), full_page=True)

            # 3. El observador pide permiso; todavía no ve nada
            login(watcher, WATCHER, "viewer")
            watcher.fill("#code", watcher.inner_text("#devcode"))
            watcher.click("#verify")
            watcher.fill("#tphone", OWNER)
            watcher.fill("#tmsg", "Soy Ana, tu hermana. Para saber que llegaste bien")
            watcher.click("#ask")
            expect(watcher.locator(".pill.pending")).to_be_visible()
            assert watcher.locator("button.open").count() == 0, "no debe haber acceso al mapa sin permiso"
            watcher.screenshot(path=str(SHOTS / "03-observador-pendiente.png"), full_page=True)

            # 4. El dueño recibe la solicitud y la aprueba (7 días, con historial)
            owner.reload()
            expect(owner.locator("button.approve")).to_be_visible()
            owner.screenshot(path=str(SHOTS / "04-solicitud-recibida.png"), full_page=True)
            owner.locator("input[type=checkbox]").check()
            owner.click("button.approve")
            expect(owner.locator(".pill.approved")).to_be_visible()

            # 5. Activa el uso compartido: el navegador pide el GPS y envía la posición
            owner.click("#toggle")
            expect(owner.locator("#banner")).to_contain_text("Se está compartiendo")
            owner.screenshot(path=str(SHOTS / "05-dispositivo-compartiendo.png"), full_page=True)

            # recorrido previo (50 a 10 minutos atrás) para que el mapa tenga historial
            token = owner.evaluate("JSON.parse(sessionStorage.getItem('session')).token")
            now = datetime.now(timezone.utc)
            trail = [(4.5900, -74.0850), (4.5930, -74.0820), (4.5955, -74.0790), (4.5970, -74.0772)]
            for i, (la, lo) in enumerate(trail):
                ts = (now - timedelta(minutes=50 - 12 * i)).isoformat()
                status = owner.evaluate("""async ([t, la, lo, ts]) => (await fetch('/api/device/locations', {method:'POST',
                    headers:{'Authorization':'Bearer '+t,'Content-Type':'application/json'},
                    body: JSON.stringify({lat:la, lon:lo, recorded_at:ts, source:'periodic'})})).status""", [token, la, lo, ts])
                assert status == 201, status

            # 6. El observador abre el mapa
            watcher.reload()
            watcher.click("button.open")
            expect(watcher.locator(".leaflet-marker-icon")).to_have_count(1)
            watcher.wait_for_timeout(600)
            watcher.screenshot(path=str(SHOTS / "06-mapa-historial.png"), full_page=True)

            # 7. Crea una zona sobre la posición actual; el dueño sale de ella
            box = watcher.locator(".leaflet-marker-icon").bounding_box()
            watcher.mouse.click(box["x"] - 22, box["y"] + box["height"] - 4)   # junto al marcador: centro de la zona
            watcher.fill("#zname", "Casa")
            watcher.fill("#zrad", "300")
            watcher.click("#addzone")
            expect(watcher.locator("path.leaflet-interactive").first).to_be_visible()
            owner.reload()
            owner.click("#now")                                  # dentro de la zona: fija el estado
            owner.click("details summary")
            owner.fill("#mlat", str(FAR[0]))
            owner.fill("#mlon", str(FAR[1]))
            owner.click("#manual")                               # ~4,6 km al norte: sale
            owner.wait_for_timeout(600)
            watcher.reload()
            watcher.click("button.open")
            expect(watcher.locator("#alerts li")).to_contain_text("salió de")
            watcher.wait_for_timeout(600)
            watcher.screenshot(path=str(SHOTS / "07-zona-alerta.png"), full_page=True)

            # 8. Transparencia: el dueño ve quién consultó, y revoca
            owner.reload()
            expect(owner.locator("#audit")).to_contain_text("consultó la ubicación")
            owner.screenshot(path=str(SHOTS / "08-dueno-registro.png"), full_page=True)
            owner.locator("button.danger", has_text="Revocar").click()
            expect(owner.locator(".pill.revoked")).to_be_visible()

            # 9. Al revocar, el observador pierde el acceso de inmediato
            watcher.reload()
            expect(watcher.locator(".pill.revoked")).to_be_visible()
            assert watcher.locator("button.open").count() == 0
            watcher.screenshot(path=str(SHOTS / "09-acceso-revocado.png"), full_page=True)
            browser.close()
        print("E2E OK: flujo completo con consentimiento, zona, alerta y revocación")
    finally:
        server.terminate()
        server.wait(10)


if __name__ == "__main__":
    main()
