#!/usr/bin/env python3
"""CASO-04: experimento educativo OFFLINE, no detector validado.

python scripts/caso04_ml.py --self-test
python scripts/caso04_ml.py

Solo lee baseline-normal.pcapng con tshark -n -r; nunca captura ni envía tráfico.
Las anomalías son registros tabulares sintéticos, NO paquetes transmitidos ni
PCAP de casos 1/2. Tests integrados para no modificar archivos de otros casos.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path
import platform
import random
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix

LAB = Path(__file__).resolve().parent.parent
CASOS = LAB / "evidencia" / "casos"
BASELINE = LAB / "evidencia" / "baseline-normal.pcapng"
TSHARK = Path(r"C:\Program Files\Wireshark\tshark.exe")
WINDOW = 10.0
SEED = 42
ATTACKER = "192.168.50.100"
DNS_SUFFIX = ".exfil.lab.local"
FEATURES = [
    "n_pkts", "n_bytes", "n_flows", "n_dst_ports", "bytes_per_flow",
    "flow_duration_mean_s", "flow_duration_max_s", "packets_per_s",
    "bytes_per_s", "flows_per_min", "n_syn", "n_syn_ack", "n_ack",
    "n_reset", "n_fin", "syn_ratio", "reset_ratio", "n_tcp_syn_attempts",
    "connections_per_min", "request_count", "response_count",
    "request_response_ratio", "requests_without_response", "requests_per_s",
    "responses_per_s", "dns_queries", "dns_responses",
    "dns_query_length_mean", "http_requests", "http_responses",
]
FIELDS = [
    "frame.number", "frame.time_relative", "ip.proto", "ipv6.nxt", "ip.src",
    "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "tcp.dstport",
    "udp.srcport", "udp.dstport", "frame.len", "tcp.flags.syn", "tcp.flags.ack",
    "tcp.flags.reset", "tcp.flags.fin", "dns.flags.response", "dns.qry.name",
    "http.request", "http.response",
]
LIMITATIONS = [
    "MUESTRA PEQUEÑA: un único baseline; ventanas correlacionadas, no sujetos independientes.",
    "No hay anomalías reales de test: solo normales reales y anomalías SINTÉTICAS tabulares.",
    "Las variantes SYN/DNS comparten fondo con su ventana real de test; no aumentan el N independiente.",
    "No permite generalización, comparación fuerte entre detectores ni medidas automáticas de bloqueo.",
    "Normal es una suposición del segmento baseline, no una certificación de ausencia de ataques.",
    "Duraciones truncadas a cada ventana; SYN únicos son intentos observados, no conexiones establecidas.",
    "Solo TCP/UDP IPv4/IPv6 decodificados; DNS/HTTP según tshark (sin descifrar TLS, primera ocurrencia).",
    "Sin validación externa ni ajuste de hiperparámetros: umbrales prefijados, no elegidos mirando test.",
]


@dataclass(frozen=True)
class Packet:
    t: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    length: int
    syn: bool = False
    ack: bool = False
    rst: bool = False
    fin: bool = False
    dns_response: int | None = None
    qname: str = ""
    http_request: bool = False
    http_response: bool = False
    origin_kind: str = "real_background"
    origin_file: str = ""
    origin_sha256: str = ""
    origin_record: str = ""


@dataclass(frozen=True)
class Segment:
    kind: str
    start: float
    end: float


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_tshark(pcap, executable=TSHARK):
    """Fail closed: shell=False, resolución desactivada, solo lectura local."""
    path = Path(pcap).resolve(strict=True)
    command = [str(executable), "-n", "-r", str(path), "-T", "fields",
               "-E", "separator=|", "-E", "occurrence=f", "-E", "quote=n"]
    for field in FIELDS:
        command.extend(["-e", field])
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                encoding="utf-8", errors="strict", check=True,
                                timeout=120, shell=False)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"tshark falló ({exc.returncode}): {exc.stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("tshark excedió 120 s; no se genera dataset parcial") from exc
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"No se pudo ejecutar/leer tshark: {exc}") from exc
    if not result.stdout.strip():
        raise RuntimeError("tshark no devolvió paquetes; no se genera dataset vacío")
    return result.stdout, result.stderr.strip(), command


def parse_packets(text, source_file, source_hash):
    packets, times = [], []
    flag = lambda value: value.lower() in ("1", "true")
    for line_number, line in enumerate(text.splitlines(), 1):
        fields = line.split("|")
        if len(fields) != len(FIELDS):
            raise ValueError(f"Fila tshark {line_number}: número de campos incorrecto")
        (frame, timestamp, ip_proto, ip6_proto, src4, src6, dst4, dst6,
         tcp_sp, tcp_dp, udp_sp, udp_dp, length, syn, ack, rst, fin,
         dns_response, qname, http_request, http_response) = fields
        try:
            t, size = float(timestamp), int(length)
            if not math.isfinite(t) or t < 0 or size < 0 or int(frame) < 1:
                raise ValueError("tiempo, tamaño o frame inválido")
            times.append(t)
            src, dst = src4 or src6, dst4 or dst6
            # Puertos decodificados permiten IPv6 con cabeceras de extensión.
            proto = "6" if tcp_sp else "17" if udp_sp else ip_proto or ip6_proto
            if proto not in ("6", "17") or not src or not dst:
                continue
            sp, dp = (tcp_sp, tcp_dp) if proto == "6" else (udp_sp, udp_dp)
            if not sp or not dp:  # Fragmento sin cabecera de transporte.
                continue
            sport, dport = int(sp), int(dp)
            if not (0 <= sport <= 65535 and 0 <= dport <= 65535):
                raise ValueError("puerto fuera de rango")
            if dns_response.lower() not in ("", "0", "1", "false", "true"):
                raise ValueError("dns.flags.response inválido")
            packets.append(Packet(
                t, src, dst, sport, dport, proto, size, flag(syn), flag(ack),
                flag(rst), flag(fin), int(flag(dns_response)) if dns_response else None,
                qname, flag(http_request), flag(http_response),
                origin_file=str(source_file), origin_sha256=source_hash,
                origin_record=f"frame:{frame}",
            ))
        except ValueError as exc:
            raise ValueError(f"Fila tshark {line_number}: {exc}") from exc
    if not packets:
        raise ValueError("No hay paquetes TCP/UDP decodificados")
    return sorted(packets, key=lambda packet: packet.t), max(times), len(times)


def markers(packet):
    result = set()
    if packet.proto == "6" and packet.src == ATTACKER and packet.syn and not packet.ack:
        result.add("syn")
    if (packet.dns_response is not None and
            packet.qname.rstrip(".").lower().endswith(DNS_SUFFIX)):
        result.add("dns")
    return result


def packet_label(packet, segments):
    """No infiere etiquetas del nombre de fichero ni del escenario completo.

    Un marcador fuera de su segmento es desconocido y provoca rechazo. Los
    paquetes de fondo sin marcador mantienen su etiqueta normal asumida.
    """
    found = markers(packet)
    applicable = {s.kind for s in segments if s.start <= packet.t < s.end}
    if found and not found.issubset(applicable):
        return "unknown"
    if not found:
        return "normal"
    return "+".join(sorted(found))


def flow_key(packet):
    # La dirección inversa pertenece al mismo flujo TCP/UDP.
    return packet.proto, tuple(sorted(((packet.src, packet.sport),
                                      (packet.dst, packet.dport))))


def window_features(packets, seconds):
    if seconds <= 0 or not math.isfinite(seconds):
        raise ValueError("Ventana inválida")
    flows = defaultdict(list)
    for packet in packets:
        flows[flow_key(packet)].append(packet)
    durations = [max(p.t for p in flow) - min(p.t for p in flow)
                 for flow in flows.values()]
    size, count = sum(p.length for p in packets), len(packets)
    syn = sum(p.syn and not p.ack for p in packets)
    reset = sum(p.rst for p in packets)
    attempts = len({flow_key(p) for p in packets if p.syn and not p.ack})
    dns_q = [p for p in packets if p.dns_response == 0]
    dns_r = sum(p.dns_response == 1 for p in packets)
    http_q = sum(p.http_request for p in packets)
    http_r = sum(p.http_response for p in packets)
    requests, responses = len(dns_q) + http_q, dns_r + http_r
    return dict(
        n_pkts=count, n_bytes=size, n_flows=len(flows),
        n_dst_ports=len({p.dport for p in packets}),
        bytes_per_flow=size / max(len(flows), 1),
        flow_duration_mean_s=float(np.mean(durations)) if durations else 0.0,
        flow_duration_max_s=max(durations, default=0.0),
        packets_per_s=count / seconds, bytes_per_s=size / seconds,
        flows_per_min=len(flows) * 60 / seconds, n_syn=syn,
        n_syn_ack=sum(p.syn and p.ack for p in packets),
        n_ack=sum(p.ack for p in packets), n_reset=reset,
        n_fin=sum(p.fin for p in packets), syn_ratio=syn / max(count, 1),
        reset_ratio=reset / max(count, 1), n_tcp_syn_attempts=attempts,
        connections_per_min=attempts * 60 / seconds,
        request_count=requests, response_count=responses,
        request_response_ratio=requests / max(responses, 1),
        requests_without_response=int(requests > 0 and responses == 0),
        requests_per_s=requests / seconds, responses_per_s=responses / seconds,
        dns_queries=len(dns_q), dns_responses=dns_r,
        dns_query_length_mean=float(np.mean([len(p.qname) for p in dns_q])) if dns_q else 0.0,
        http_requests=http_q, http_responses=http_r,
    )


def aggregate(packets, capture_end, window=WINDOW, segments=(), metadata=None):
    """Conserva ventanas vacías; intervalos [inicio, fin); descarta cola parcial."""
    if not math.isfinite(window) or window <= 0 or capture_end < 0:
        raise ValueError("Duración de ventana/captura inválida")
    complete = math.floor(capture_end / window)
    buckets = [[] for _ in range(complete)]
    for packet in packets:
        if not math.isfinite(packet.t) or packet.t < 0:
            raise ValueError("Tiempo de paquete inválido")
        index = math.floor(packet.t / window)
        if index < complete:
            buckets[index].append(packet)
    records = []
    for index, bucket in enumerate(buckets):
        labels = [packet_label(p, segments) for p in bucket]
        if "unknown" in labels:
            raise ValueError(f"Marcador fuera de segmento autorizado en ventana {index}")
        kinds = sorted({label for label in labels if label != "normal"})
        row = dict(metadata or {})
        row.update(window_id=index, window_start_s=index * window,
                   window_end_s=(index + 1) * window, window_seconds=window,
                   label=int(bool(kinds)), label_name="+".join(kinds) or "normal",
                   label_basis="segment+packet_marker" if kinds else "baseline_segment_assumption",
                   normal_packets=labels.count("normal"),
                   anomaly_packets=sum(label != "normal" for label in labels))
        row.update(window_features(bucket, window))
        records.append(row)
    return pd.DataFrame(records)


def temporal_split(normal):
    """60% inicial train, una ventana embargo, resto test; antes de todo fit."""
    if len(normal) < 6 or not (normal["label"] == 0).all():
        raise ValueError("Se requieren al menos 6 ventanas normales para separar train/test")
    ordered = normal.sort_values("window_start_s").reset_index(drop=True).copy()
    if ordered["window_id"].duplicated().any():
        raise ValueError("Identificadores de ventana duplicados")
    if (ordered["window_start_s"].to_numpy()[1:] <
            ordered["window_end_s"].to_numpy()[:-1]).any():
        raise ValueError("Ventanas temporales solapadas")
    train_count = math.floor(len(ordered) * 0.6)
    ordered["split"] = "test"
    ordered.loc[:train_count - 1, "split"] = "train"
    ordered.loc[train_count, "split"] = "embargo"
    if len(ordered[ordered["split"] == "test"]) < 2:
        raise ValueError("Test normal insuficiente")
    return ordered


def synthetic_scenarios(packets, normal):
    """Añade registros a fondos exclusivamente de test. No fabrica PCAP."""
    rng = random.Random(SEED)
    scenarios, packet_records, segment_records = [], [], []
    for row in normal[normal["split"] == "test"].to_dict("records"):
        start, end = row["window_start_s"], row["window_end_s"]
        background = [p for p in packets if start <= p.t < end]
        for kind in ("syn", "dns"):
            scenario = f"{kind}-w{row['window_id']:03d}"
            segment = Segment(kind, start + 2, end - 2)
            added = []
            count = max(12, len(background) // 2) + rng.randrange(12, 37)
            for index in range(count):
                t = segment.start + (index + 0.25) * (segment.end - segment.start) / count
                origin = dict(origin_kind="synthetic_injected",
                              origin_file="caso04_ml.py:synthetic_scenarios:v1",
                              origin_sha256=sha256_file(Path(__file__)),
                              origin_record=f"seed:{SEED}:{scenario}:{index}")
                if kind == "syn":
                    added.append(Packet(t, ATTACKER, "192.168.50.20", 40000 + index,
                                        80, "6", 60, syn=True, **origin))
                else:
                    token = "".join(rng.choices("abcdef0123456789", k=40))
                    qname = token + DNS_SUFFIX
                    query = Packet(t, ATTACKER, "192.168.50.30", 45000 + index,
                                   53, "17", 42 + len(qname) + 6,
                                   dns_response=0, qname=qname, **origin)
                    added.append(query)
                    if index % 2 == 0:
                        added.append(replace(query, t=t + 0.005, src=query.dst,
                                             dst=query.src, sport=query.dport,
                                             dport=query.sport, length=query.length + 16,
                                             dns_response=1,
                                             origin_record=query.origin_record + ":response"))
            combined = sorted(background + added, key=lambda p: p.t)
            for index, packet in enumerate(combined):
                packet_records.append(dict(
                    scenario_id=scenario, parent_window_id=row["sample_id"],
                    packet_id=f"{scenario}:{index}", label_name=packet_label(packet, [segment]),
                    **asdict(packet)))
            segment_records.append(dict(
                scenario_id=scenario, parent_window_id=row["sample_id"],
                **asdict(segment),
                marker=f"src={ATTACKER}; TCP SYN=1 ACK=0" if kind == "syn" else f"dns.qry.name endswith {DNS_SUFFIX}",
                data_kind="synthetic",
            ))
            scenarios.append((row, scenario, combined, segment))
    return scenarios, pd.DataFrame(packet_records), pd.DataFrame(segment_records)


def fit_predict(dataset):
    train = dataset[dataset["split"] == "train"]
    test = dataset[dataset["split"] == "test"].copy()
    if train.empty or test.empty or not (train["label"] == 0).all():
        raise ValueError("Entrenamiento/test inválidos")
    if not (train["data_kind"] == "real").all():
        raise ValueError("Solo se entrena con normales reales")
    if set(train["parent_window_id"]) & set(test["parent_window_id"]):
        raise ValueError("Leakage: ventana padre compartida entre train y test")
    if train["window_end_s"].max() > test["window_start_s"].min() - WINDOW:
        raise ValueError("Leakage: falta separación temporal con embargo")
    if not np.isfinite(dataset[FEATURES].to_numpy(dtype=float)).all():
        raise ValueError("Features no finitas")
    # Lista explícita: nunca entran fuente, tiempo, origen, etiqueta o partición.
    x_train, x_test = train[FEATURES], test[FEATURES]
    mean = x_train.mean()
    std = x_train.std(ddof=0)
    constant = std <= 1e-12
    safe_std = std.mask(constant, 1.0)
    z = (x_test - mean).abs().div(safe_std)
    # Feature constante: desviación > tolerancia absoluta 1e-9 da alerta.
    # Convención explícita, no se divide por epsilon ni se ajusta usando test.
    changed_constant = (x_test.loc[:, constant] - mean[constant]).abs().gt(1e-9).any(axis=1)
    test["pred_zscore"] = (z.loc[:, ~constant].gt(3.0).any(axis=1) | changed_constant).astype(int)
    test["score_zscore_nonconstant"] = z.loc[:, ~constant].max(axis=1).fillna(0.0)
    test["zscore_constant_changed"] = changed_constant
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=SEED,
                            n_jobs=1)
    model.fit(x_train)
    test["pred_iforest"] = (model.predict(x_test) == -1).astype(int)
    test["score_iforest"] = -model.decision_function(x_test)
    state = dict(
        train_sample_ids=train["sample_id"].tolist(), features=FEATURES,
        zscore_mean=mean.to_dict(), zscore_std=std.to_dict(),
        zscore_constant_features=std[constant].index.tolist(),
        zscore_threshold=3.0, zscore_constant_tolerance=1e-9,
        iforest=dict(n_estimators=200, contamination="auto", random_state=SEED,
                     offset=float(model.offset_)),
    )
    return test, state


def safe_ratio(numerator, denominator):
    return float(numerator / denominator) if denominator else None


def metrics_for(frame, prediction):
    tn, fp, fn, tp = confusion_matrix(frame["label"], frame[prediction], labels=[0, 1]).ravel()
    tn, fp, fn, tp = map(int, (tn, fp, fn, tp))
    negatives, positives = tn + fp, tp + fn
    both = negatives > 0 and positives > 0
    return dict(
        n=len(frame), normal=negatives, anomaly=positives,
        confusion_matrix=[[tn, fp], [fn, tp]],
        accuracy=safe_ratio(tn + tp, len(frame)),
        precision=safe_ratio(tp, tp + fp) if both else None,
        recall=safe_ratio(tp, positives),
        f1=safe_ratio(2 * tp, 2 * tp + fp + fn) if both else None,
        false_positive_rate=safe_ratio(fp, negatives),
        specificity=safe_ratio(tn, negatives),
        warning=None if both else "Una sola clase: precision/F1 no informadas; sin evaluación discriminativa completa",
    )


def evaluate(test):
    groups = {
        "real_normal_only": test[test["data_kind"] == "real"],
        "synthetic_syn_only": test[(test["data_kind"] == "synthetic") & (test["label_name"] == "syn")],
        "synthetic_dns_only": test[(test["data_kind"] == "synthetic") & (test["label_name"] == "dns")],
        "mixed_didactic_NOT_independent": test,
    }
    return {name: {model: metrics_for(frame, column)
                   for model, column in (("zscore", "pred_zscore"), ("iforest", "pred_iforest"))}
            for name, frame in groups.items()}


def backup_artifacts():
    """Copia cada versión antes de sobrescribir; no elimina screenshots."""
    files = sorted(p for p in CASOS.glob("caso04-*") if p.is_file())
    if not files:
        return None
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    destination = CASOS / "revision-ml-anterior" / name
    destination.mkdir(parents=True, exist_ok=False)
    records = []
    for source in files:
        target = destination / source.name
        shutil.copy2(source, target)
        digest = sha256_file(source)
        if digest != sha256_file(target):
            raise RuntimeError(f"Backup no coincide: {source}")
        records.append(dict(original=str(source), backup=str(target), sha256=digest))
    (destination / "caso04-backup-manifest.json").write_text(json.dumps(dict(
        status="historical_superseded", files=records,
        reason="Versión anterior; no usar screenshots históricos como evidencia vigente",
    ), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(destination)


def plots(dataset, test, metrics):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.8))
    for ax, model, title in zip(axes, ("zscore", "iforest"), ("Z-score prefijado", "IsolationForest")):
        matrix = np.array(metrics["mixed_didactic_NOT_independent"][model]["confusion_matrix"])
        ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max(1, matrix.max()))
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(matrix[i, j]), ha="center", va="center", fontsize=18,
                        color="white" if matrix[i, j] > matrix.max() / 2 else "black")
        ax.set(xticks=[0, 1], yticks=[0, 1], xticklabels=["Normal", "Anomalía"],
               yticklabels=["Normal real", "Anomalía\nsintética"],
               xlabel="Predicción", ylabel="Etiqueta de procedencia", title=title)
    fig.suptitle("CASO-04 · Test didáctico mixto · ventanas iguales de 10 s")
    n_real = sum(test["data_kind"] == "real")
    n_syn = sum(test["data_kind"] == "synthetic")
    fig.text(0.5, 0.025, f"{n_real} normales reales + {n_syn} variantes sintéticas dependientes; NO validación de ataques reales.", ha="center", fontsize=10)
    fig.tight_layout(rect=(0, 0.07, 1, 0.94))
    fig.savefig(CASOS / "caso04-matriz-confusion.png", dpi=160)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(10, 5.8))
    styles = [
        ((dataset["split"] == "train"), "Train real", "o", "#197447"),
        ((dataset["split"] == "embargo"), "Embargo (no usado)", "x", "#777777"),
        ((dataset["split"] == "test") & (dataset["data_kind"] == "real"), "Test real normal", "s", "#2058a5"),
        (dataset["label_name"] == "syn", "Test SYN sintético", "^", "#c54e16"),
        (dataset["label_name"] == "dns", "Test DNS sintético", "D", "#7c479e"),
    ]
    for mask, label, marker, color in styles:
        group = dataset[mask]
        ax.scatter(group["connections_per_min"], group["requests_per_s"],
                   label=f"{label} (n={len(group)})", marker=marker, color=color, s=65, alpha=0.75)
    ax.set(xlabel="Intentos TCP SYN únicos observados por minuto (no conexiones establecidas)",
           ylabel="Peticiones DNS + HTTP por segundo",
           title="CASO-04 · Rasgos por ventana de 10 s, sin etiquetas como features")
    ax.legend(loc="best", fontsize=9)
    ax.grid(alpha=0.2)
    fig.text(0.5, 0.025, "La separación visual fue inducida por el generador; puntos superpuestos, sin jitter. No implica generalización.", ha="center", fontsize=9)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.savefig(CASOS / "caso04-scatter.png", dpi=160)
    plt.close(fig)


def main(executable=TSHARK):
    test_result, test_report = run_self_tests()
    if not test_result.wasSuccessful():
        raise RuntimeError("Pruebas unitarias fallidas; no regenerar artefactos:\n" + test_report)
    if not CASOS.is_dir():
        raise RuntimeError(f"No existe directorio de artefactos: {CASOS}")
    source_hash = sha256_file(BASELINE)
    raw, stderr, command = run_tshark(BASELINE, executable)
    if source_hash != sha256_file(BASELINE):
        raise RuntimeError("Baseline cambió durante la lectura; repetir sobre una copia estable")
    packets, capture_end, total_frames = parse_packets(raw, BASELINE, source_hash)
    baseline_text = pd.DataFrame([
        dict(window_id=math.floor(p.t / WINDOW), label_name=packet_label(p, []),
             label_basis="baseline_segment_assumption", **asdict(p)) for p in packets
    ]).to_csv(index=False, lineterminator="\n")
    normal = aggregate(packets, capture_end, metadata=dict(
        data_kind="real", source_file=str(BASELINE), source_sha256=source_hash,
        packet_table=str(CASOS / "caso04-baseline-paquetes.csv"),
        packet_table_sha256=sha256_text(baseline_text),
        baseline_file=str(BASELINE), baseline_sha256=source_hash,
    ))
    normal["sample_id"] = [f"real:{source_hash[:12]}:w{index:03d}" for index in normal["window_id"]]
    normal["parent_window_id"] = normal["sample_id"]
    normal["scenario_id"] = "baseline"
    normal["segments_json"] = "[]"
    normal = temporal_split(normal)  # ANTES de sintetizar o ajustar estadísticas/modelo.
    scenarios, synthetic_packets, segments = synthetic_scenarios(packets, normal)
    synthetic_text = synthetic_packets.to_csv(index=False, lineterminator="\n")
    synthetic_hash = sha256_text(synthetic_text)
    synthetic_rows = []
    for parent, scenario, combined, segment in scenarios:
        frame = aggregate(combined, parent["window_end_s"], segments=[segment])
        row = frame[frame["window_id"] == parent["window_id"]].iloc[0].to_dict()
        row.update(
            sample_id=f"synthetic:{scenario}", parent_window_id=parent["sample_id"],
            scenario_id=scenario, split="test", data_kind="synthetic",
            source_file=str(CASOS / "caso04-sinteticos-paquetes.csv"),
            source_sha256=synthetic_hash,
            packet_table=str(CASOS / "caso04-sinteticos-paquetes.csv"),
            packet_table_sha256=synthetic_hash,
            baseline_file=str(BASELINE), baseline_sha256=source_hash,
            segments_json=json.dumps([asdict(segment)], sort_keys=True),
        )
        synthetic_rows.append(row)
    dataset = pd.concat([normal, pd.DataFrame(synthetic_rows)], ignore_index=True)
    test, state = fit_predict(dataset)
    metrics = evaluate(test)
    dropped = [p for p in packets if p.t >= len(normal) * WINDOW]
    details = dict(
        window_seconds=WINDOW, interval="[start,end)", tail_policy="drop_partial",
        capture_end_s=capture_end, capture_frames=total_frames,
        decoded_tcp_udp_packets=len(packets), excluded_other_or_undecoded=total_frames - len(packets),
        tail_seconds=capture_end - len(normal) * WINDOW, tail_tcp_udp_packets=len(dropped),
        real_windows=len(normal), real_split_counts=normal["split"].value_counts().to_dict(),
        synthetic_windows=len(synthetic_rows), seed=SEED,
    )
    # Solo desde aquí se escriben artefactos; todos los anteriores quedan respaldados.
    backup = backup_artifacts()
    texts = {
        "caso04-pruebas.txt": test_report,
        "caso04-baseline-paquetes.csv": baseline_text,
        "caso04-sinteticos-paquetes.csv": synthetic_text,
        "caso04-segmentos.csv": segments.to_csv(index=False, lineterminator="\n"),
        "caso04-dataset.csv": dataset.to_csv(index=False, lineterminator="\n"),
        "caso04-predicciones.csv": test.to_csv(index=False, lineterminator="\n"),
        "caso04-modelo-parametros.json": json.dumps(state, indent=2, ensure_ascii=False),
        "caso04-metricas.json": json.dumps(metrics, indent=2, ensure_ascii=False),
    }
    train_ids = normal[normal["split"] == "train"]["window_id"].tolist()
    test_ids = normal[normal["split"] == "test"]["window_id"].tolist()
    lines = ["CASO-04 · REVISIÓN METODOLÓGICA · SOLO OFFLINE", "",
             "DATOS REALES: únicamente baseline normal asumido. ANOMALÍAS: SOLO SINTÉTICAS.",
             f"Baseline SHA256: {source_hash}",
             f"Ventanas completas: {len(normal)} de {WINDOW:g} s; cola descartada: {details['tail_seconds']:.6f} s ({len(dropped)} paquetes TCP/UDP).",
             f"Train normal: ventanas {train_ids}; embargo: {normal[normal['split'] == 'embargo']['window_id'].tolist()}; test normal: {test_ids}.",
             f"Test sintético: {len(synthetic_rows)} variantes sobre {len(test_ids)} ventanas padre de test (SYN/DNS).",
             f"Features ({len(FEATURES)}): {', '.join(FEATURES)}", "",
             "Resultados SOLO TEST; filas=etiqueta, columnas=predicción; orden [normal, anomalía].",
             "N/A = no definida o no informada por clase única; no se convierte en cero."]
    for group, models in metrics.items():
        lines.append(f"\n{group}:")
        for model, values in models.items():
            fmt = lambda x: "N/A" if x is None else f"{x:.3f}"
            lines.append(f"  {model}: n={values['n']}, CM={values['confusion_matrix']}; " +
                         "; ".join(f"{key}={fmt(values[key])}" for key in
                                   ("accuracy", "precision", "recall", "f1", "false_positive_rate")))
    lines.extend(["", "ADVERTENCIAS:"] + ["- " + message for message in LIMITATIONS])
    lines.extend(["", "Z-score: media/std SOLO train (ddof=0); |z|>3 en cualquier feature no constante.",
                  "Feature constante: alerta si cambio absoluto >1e-9. Sin calibración sobre test.",
                  "IsolationForest: 200 árboles, contamination=auto, semilla 42, umbral nativo (offset=-0.5).",
                  "Screenshot caso04-consola.png HISTÓRICO/OBSOLETO: conservar y recapturar como caso04-consola-revisada.png."])
    texts["caso04-metricas.txt"] = "\n".join(lines) + "\n"
    screenshots = sorted(CASOS.glob("caso04-consola*.png"))
    texts["caso04-pantallazos-obsoletos.txt"] = (
        "OBSOLETOS PARA ESTA EJECUCIÓN; conservados sin modificar.\n" +
        "\n".join(f"{path.name} SHA256={sha256_file(path)}" for path in screenshots) +
        "\nRecapturar consola con pruebas y métricas vigentes como caso04-consola-revisada.png; no sustituir el original.\n")
    for name, text in texts.items():
        (CASOS / name).write_text(text, encoding="utf-8", newline="\n")
    plots(dataset, test, metrics)
    manifest = dict(
        generated_utc=datetime.now(timezone.utc).isoformat(),
        baseline_file=str(BASELINE), baseline_sha256=source_hash,
        script_sha256=sha256_file(Path(__file__)), offline_only=True,
        inputs_case01_case02_used=False, backup_directory=backup,
        tshark_command=command, tshark_stderr=stderr,
        versions=dict(python=platform.python_version(), pandas=pd.__version__,
                      numpy=np.__version__, sklearn=sklearn.__version__, matplotlib=matplotlib.__version__),
        details=details, limitations=LIMITATIONS,
        artifact_sha256={name: sha256_file(CASOS / name) for name in sorted(
            list(texts) + ["caso04-matriz-confusion.png", "caso04-scatter.png"])},
    )
    (CASOS / "caso04-manifiesto.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    print(texts["caso04-metricas.txt"])
    print(f"Pruebas unitarias: {test_result.testsRun} OK (caso04-pruebas.txt)")
    print(f"Backup anterior: {backup}\nArtefactos: {CASOS}")


class MethodologyTests(unittest.TestCase):
    """No red ni escrituras; subprocess se sustituye en todas sus pruebas."""

    @staticmethod
    def packet(t=0.0, **kwargs):
        return Packet(t, "192.168.50.10", "192.168.50.20", 41000, 80, "6", 60, **kwargs)

    def normal_frame(self):
        frame = aggregate([self.packet(2)], 100)
        frame["sample_id"] = [f"real:{i}" for i in frame["window_id"]]
        frame["parent_window_id"] = frame["sample_id"]
        frame["data_kind"] = "real"
        return temporal_split(frame)

    def test_equal_windows_boundaries_empty_and_tail(self):
        frame = aggregate([self.packet(0), self.packet(10), self.packet(39.9), self.packet(40.1)], 45)
        self.assertEqual(frame["n_pkts"].tolist(), [1, 1, 0, 1])
        self.assertEqual(frame["window_seconds"].tolist(), [10.0] * 4)
        self.assertEqual(frame["window_end_s"].tolist(), [10, 20, 30, 40])
        self.assertTrue(np.isfinite(frame[FEATURES].to_numpy()).all())

    def test_reject_bad_window(self):
        with self.assertRaises(ValueError):
            aggregate([], 20, window=0)

    def test_bidirectional_duration_and_retransmissions(self):
        first = self.packet(1, syn=True)
        duplicate = replace(first, t=2)
        response = replace(first, t=4, src=first.dst, dst=first.src,
                           sport=first.dport, dport=first.sport, syn=True, ack=True)
        result = window_features([first, duplicate, response], 10)
        self.assertEqual(result["n_flows"], 1)
        self.assertEqual(result["bytes_per_flow"], 180)
        self.assertEqual(result["flow_duration_mean_s"], 3)
        self.assertEqual(result["n_syn"], 2)
        self.assertEqual(result["n_syn_ack"], 1)
        self.assertEqual(result["connections_per_min"], 6)

    def test_requests_responses_and_zero_denominator(self):
        query = replace(self.packet(1), proto="17", dport=53, dns_response=0, qname="web.lab.local")
        response = replace(query, t=2, dns_response=1)
        result = window_features([query, response], 10)
        self.assertEqual(result["request_response_ratio"], 1)
        self.assertEqual(result["requests_without_response"], 0)
        result = window_features([query, query], 10)
        self.assertEqual(result["request_response_ratio"], 2)
        self.assertEqual(result["requests_without_response"], 1)

    def test_syn_labels_require_origin_flags_and_segment(self):
        attack = replace(self.packet(2, syn=True), src=ATTACKER)
        segment = Segment("syn", 2, 8)
        self.assertEqual(packet_label(attack, [segment]), "syn")
        self.assertEqual(packet_label(replace(attack, src="192.168.50.101"), [segment]), "normal")
        self.assertEqual(packet_label(replace(attack, ack=True), [segment]), "normal")
        self.assertEqual(packet_label(replace(attack, t=8), [segment]), "unknown")
        with self.assertRaises(ValueError):
            aggregate([attack], 10)  # No etiquetar todo un PCAP como ataque.

    def test_dns_suffix_and_background_labels(self):
        dns = replace(self.packet(3), proto="17", dport=53, dns_response=0,
                      qname="ABCD.EXFIL.LAB.LOCAL.")
        segment = Segment("dns", 2, 8)
        self.assertEqual(packet_label(dns, [segment]), "dns")
        self.assertEqual(packet_label(replace(dns, dns_response=1), [segment]), "dns")
        self.assertEqual(packet_label(replace(dns, qname="evil.exfil.lab.local.other"), [segment]), "normal")
        frame = aggregate([dns, self.packet(1), self.packet(12)], 20, segments=[segment])
        self.assertEqual(frame["label"].tolist(), [1, 0])
        self.assertEqual(frame["normal_packets"].tolist(), [1, 1])
        self.assertEqual(frame["anomaly_packets"].tolist(), [1, 0])

    def test_temporal_split_disjoint_and_embargo(self):
        frame = self.normal_frame()
        self.assertEqual(frame["split"].tolist(), ["train"] * 6 + ["embargo"] + ["test"] * 3)
        train, test = frame[frame["split"] == "train"], frame[frame["split"] == "test"]
        self.assertFalse(set(train["parent_window_id"]) & set(test["parent_window_id"]))
        self.assertLess(train["window_end_s"].max(), test["window_start_s"].min())

    def test_insufficient_or_anomalous_training_rejected(self):
        frame = aggregate([self.packet()], 30)
        with self.assertRaises(ValueError):
            temporal_split(frame)
        frame = aggregate([self.packet()], 100)
        frame.loc[0, "label"] = 1
        with self.assertRaises(ValueError):
            temporal_split(frame)

    def test_fit_sees_only_train_features_and_rejects_leakage(self):
        frame = self.normal_frame()
        with patch.object(IsolationForest, "fit", autospec=True) as fit, \
                patch.object(IsolationForest, "predict", return_value=np.ones(3)), \
                patch.object(IsolationForest, "decision_function", return_value=np.zeros(3)):
            def mark_fitted(model, x):
                model.offset_ = -0.5
                return model
            fit.side_effect = mark_fitted
            _, state = fit_predict(frame)
            trained = fit.call_args.args[1]
            self.assertEqual(list(trained.columns), FEATURES)
            self.assertEqual(len(trained), 6)
            self.assertEqual(state["zscore_mean"]["n_pkts"], 1 / 6)
        frame.loc[frame["split"] == "test", "parent_window_id"] = frame.loc[0, "parent_window_id"]
        with self.assertRaisesRegex(ValueError, "Leakage"):
            fit_predict(frame)

    def test_test_extremes_do_not_change_fitted_statistics(self):
        frame = self.normal_frame()
        _, first = fit_predict(frame)
        frame.loc[frame["split"] == "test", FEATURES] = 999
        _, second = fit_predict(frame)
        self.assertEqual(first, second)

    def test_synthetic_reproducible_and_only_test_parents(self):
        frame = self.normal_frame()
        _, first, segments = synthetic_scenarios([self.packet(72)], frame)
        _, second, _ = synthetic_scenarios([self.packet(72)], frame)
        pd.testing.assert_frame_equal(first, second)
        self.assertEqual(set(first["parent_window_id"]), set(frame.loc[frame["split"] == "test", "sample_id"]))
        self.assertFalse((first["label_name"] == "unknown").any())
        self.assertIn("normal", set(first["label_name"]))
        self.assertEqual(set(segments["kind"]), {"syn", "dns"})

    def test_single_class_metrics_are_not_fake_zeros(self):
        values = metrics_for(pd.DataFrame({"label": [0, 0], "prediction": [0, 1]}), "prediction")
        self.assertIsNone(values["recall"])
        self.assertIsNone(values["precision"])
        self.assertIsNone(values["f1"])
        self.assertEqual(values["false_positive_rate"], 0.5)

    def test_subprocess_nonzero(self):
        with patch("subprocess.run", side_effect=subprocess.CalledProcessError(2, "tshark", stderr="bad capture")):
            with self.assertRaisesRegex(RuntimeError, "bad capture"):
                run_tshark(Path(__file__))

    def test_subprocess_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 120)):
            with self.assertRaisesRegex(RuntimeError, "120 s"):
                run_tshark(Path(__file__))

    def test_subprocess_missing_binary(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("missing executable")):
            with self.assertRaisesRegex(RuntimeError, "ejecutar/leer"):
                run_tshark(Path(__file__))

    def test_subprocess_empty_output(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaisesRegex(RuntimeError, "no devolvió"):
                run_tshark(Path(__file__))

    def test_subprocess_readonly_arguments_and_checks(self):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "data", "warning")) as run:
            _, warning, command = run_tshark(Path(__file__))
            self.assertIn("-n", command)
            self.assertIn("-r", command)
            self.assertNotIn("-i", command)
            self.assertNotIn("-w", command)
            self.assertTrue(run.call_args.kwargs["check"])
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertEqual(warning, "warning")

    def test_parse_boolean_dns_flags_across_tshark_versions(self):
        for value, expected in (("False", 0), ("True", 1), ("0", 0), ("1", 1)):
            with self.subTest(value=value):
                record = {field: "" for field in FIELDS}
                record.update({"frame.number": "7", "frame.time_relative": "0.42",
                               "ip.proto": "17", "ip.src": "192.168.50.10",
                               "ip.dst": "192.168.50.53", "udp.srcport": "50000",
                               "udp.dstport": "53", "frame.len": "100",
                               "dns.flags.response": value, "dns.qry.name": "web.lab.local"})
                packets, end, frames = parse_packets("|".join(record[f] for f in FIELDS), "baseline", "sha")
                self.assertEqual(packets[0].dns_response, expected)
                self.assertEqual(packets[0].origin_record, "frame:7")
                self.assertEqual((end, frames), (0.42, 1))

    def test_malformed_extraction_fails(self):
        with self.assertRaises(ValueError):
            parse_packets("not|enough|fields", "baseline", "sha")
        with self.assertRaises(ValueError):
            parse_packets("", "baseline", "sha")


def run_self_tests():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(MethodologyTests)
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    report = (f"CASO-04 · pruebas unitarias offline\nScript SHA256: {sha256_file(Path(__file__))}\n" +
              stream.getvalue())
    return result, report


def cli():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Tests offline sin escribir artefactos")
    parser.add_argument("--tshark", type=Path, default=TSHARK, help="Ejecutable local tshark")
    args = parser.parse_args()
    if args.self_test:
        result, report = run_self_tests()
        print(report)
        return 0 if result.wasSuccessful() else 1
    try:
        main(args.tshark)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"CASO-04 ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(cli())
