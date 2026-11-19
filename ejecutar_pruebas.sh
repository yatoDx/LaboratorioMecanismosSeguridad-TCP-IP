#!/usr/bin/env bash
# Ejecuta todas las pruebas automáticas del repositorio (Parte I y Parte II).
set -euo pipefail
cd "$(dirname "$0")"
echo "== Parte I =="; python3 -m pytest -q
echo "== Parte II =="; (cd parte2 && python3 -m pytest -q)
echo "Todo en orden."
