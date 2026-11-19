#!/usr/bin/env python3
"""Regresiones Parte I. Solo datos en memoria y lectura offline de PCAP existentes.
Ejecutar tras generadores: python -m unittest discover -s <scripts> -p test_casos_parte1.py -v
"""
from pathlib import Path
import shutil
import struct
import subprocess
import unittest
from unittest.mock import patch

import analizar_caso01 as c1
import analizar_caso02 as c2
import analizar_caso03 as c3
import analizar_caso05 as c5
import analizar_caso06 as c6
import analizar_caso07 as c7
import analizar_caso08 as c8
import gen_caso01_synflood as g1
import gen_caso06_udp as g6


def tcp(t, flags=2, seq=100, ack=0, reverse=False, **overrides):
    row = dict(t=t, src="192.168.50.10", sport=31000, dst="192.168.50.20", dport=80,
               flags=flags, seq=seq, ack=ack, length=0, stream=0)
    if reverse:
        row["src"], row["dst"] = row["dst"], row["src"]
        row["sport"], row["dport"] = row["dport"], row["sport"]
    row.update(overrides)
    return row


def handshake():
    return [tcp(0), tcp(.1, 18, 200, 101, True), tcp(.2, 16, 101, 201)]


class TestCorrecciones(unittest.TestCase):
    def test_bucket_burst_refill_and_cap(self):
        b = g1.TokenBucket()
        self.assertTrue(all(b.allow(0) for _ in range(20)))
        self.assertFalse(b.allow(0))
        self.assertFalse(b.allow(.099))
        self.assertTrue(b.allow(.1))
        self.assertTrue(all(b.allow(100) for _ in range(20)))
        self.assertFalse(b.allow(100))
        with self.assertRaises(ValueError):
            b.allow(99)

    def test_bucket_keeps_packets_in_second_half(self):
        b = g1.TokenBucket()
        times = [12 + 10*i/199 for i in range(200)]
        allowed = [t for t in times if b.allow(t)]
        self.assertEqual(len(allowed), 120)
        self.assertTrue(any(t > 21 for t in allowed))
        self.assertLessEqual(len(allowed), 20 + 10*(times[-1]-times[0]))

    def test_categories_exclusive(self):
        rows = [tcp(0, f) for f in (2, 18, 16, 24, 17, 20, 0)]
        counts = c1.clasificar(rows)
        self.assertEqual(sum(counts.values()), len(rows))
        self.assertEqual(counts["ACK_sin_SYN_FIN_RST"], 2)
        self.assertEqual(counts["SYN_ACK"], 1)

    def test_handshake_retransmission_deduplicated(self):
        rows = handshake() + [tcp(.01), tcp(.15, 18, 200, 101, True), tcp(.3, 16, 101, 201)]
        result = c1.handshakes(rows)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["completed"], .2)

    def test_wrong_ack_or_tuple_cannot_complete(self):
        for ack in (tcp(.2, 16, 101, 999), tcp(.2, 16, 101, 201, sport=9999)):
            result = c1.handshakes(handshake()[:2] + [ack])
            self.assertIsNone(result[0]["completed"])

    def test_timeout_missing_synack_and_rst(self):
        for rows in ([tcp(0), tcp(.2, 16, 101, 201)],
                     handshake()[:2] + [tcp(11, 16, 101, 201)],
                     handshake()[:2] + [tcp(.15, 4), tcp(.2, 16, 101, 201)]):
            self.assertIsNone(c1.handshakes(rows)[0]["completed"])

    def test_sequence_wrap(self):
        rows = [tcp(0, seq=2**32-1), tcp(.1, 18, 2**32-1, 0, True), tcp(.2, 16, 0, 0)]
        self.assertEqual(c1.handshakes(rows)[0]["completed"], .2)

    def test_windows_include_idle_and_exact_edges(self):
        self.assertEqual(c1.ventanas([0, .499999, .5, 1], .5, 1.5), [2, 1, 1, 0])
        self.assertEqual(c1.ventanas([.3], .1, .5), [0, 0, 0, 1, 0, 0])
        self.assertEqual(c1.ventanas([], 1, 2), [0, 0, 0])
        with self.assertRaises(ValueError):
            c1.ventanas([0], 0)

    def test_tshark_failure_not_empty_success(self):
        with patch.object(c1.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "bad pcap")):
            with self.assertRaisesRegex(RuntimeError, "bad pcap"):
                c1.campos("missing.pcap", ["frame.number"])

    def test_dns_entropy_uses_longest_label(self):
        label, length, entropy, suffix = c2.caracteristicas("AAAAAA.abcdef.test.")
        self.assertEqual((label, length, entropy), ("aaaaaa", 6, 0))
        self.assertGreater(c2.shannon("aaaaaa.abcdef.test"), entropy)
        self.assertEqual(suffix, "aaaaaa.abcdef.test")
        self.assertLessEqual(c2.caracteristicas("0123456789abcdef.exfil.lab.local")[2], 4)

    def test_dns_heuristic_boundaries(self):
        self.assertFalse(c2.sospechosa(30, 3.5))
        self.assertTrue(c2.sospechosa(31, 0))
        self.assertTrue(c2.sospechosa(20, 3.6))

    def test_real_dns_query_source_is_separate(self):
        rows = c2.consultas_log((c1.CASOS / "caso02-dnsmasq-log.txt").read_text(encoding="utf-8"))
        demo = [(q, ip) for q, ip in rows if q.endswith(".exfil.lab.local")]
        self.assertEqual(len(demo), 1)
        self.assertEqual(demo[0][1], "192.168.50.53")

    def test_host_inventory_requires_listen_and_retains_pid(self):
        text = "TCP 0.0.0.0:5432 0.0.0.0:0 LISTENING 6404\nTCP 0.0.0.0:445 0.0.0.0:0 ESTABLISHED 4"
        self.assertEqual(c3.inventario_host(text), [("0.0.0.0", 5432, 6404)])

    def test_rst_without_ack_not_forgery(self):
        rows = handshake() + [tcp(.5, 4, 101, 0), tcp(.6, 4, 400000, 0, src="192.168.50.100")]
        states = [state for _, state in c5.clasificar_resets(rows)]
        self.assertEqual(states, ["tupla con handshake observado", "fuera de flujo observado"])

    def test_dns_wire_question_and_response(self):
        q, r = g6.dns_messages()
        self.assertEqual(struct.unpack("!6H", q[:12]), (0x5000, 0x100, 1, 0, 0, 0))
        self.assertEqual(q[-4:], b"\x00\x01\x00\x01")
        hdr = struct.unpack("!6H", r[:12])
        self.assertTrue(hdr[1] & 0x8000)
        self.assertEqual(hdr[2:4], (1, 1))
        self.assertEqual(r[-4:], b"\xc0\xa8\x32\x14")
        self.assertEqual((len(g6.PEQ), len(g6.GRANDE), g6.PORT), (48, 468, 40000))

    def test_udp_rates_are_per_second(self):
        counts, byte_counts, pps, bps = c6.tasas([dict(t=.1, frame=90), dict(t=.5, frame=510)])
        self.assertEqual(counts, [1, 1])
        self.assertEqual(byte_counts, [90, 510])
        self.assertEqual(pps, [2, 2])
        self.assertEqual(bps, [180, 1020])

    def test_udp_pairs_exclude_unmatched_or_dns(self):
        request = dict(t=0, src=g6.VICTIMA, dst=g6.REFLECTOR, sport=52000, dport=g6.PORT)
        reply = dict(t=.1, src=g6.REFLECTOR, dst=g6.VICTIMA, sport=g6.PORT, dport=52000)
        self.assertEqual(len(c6.pares_modelo([request, reply, dict(reply, t=.2, dport=52001)])), 1)
        self.assertEqual(c6.pares_modelo([dict(request, dport=53), reply]), [])

    def test_icmp_payload_not_frame(self):
        self.assertEqual(c7.payload_echo(60, 20), 32)
        self.assertEqual(c7.payload_echo(1317, 20), 1289)
        with self.assertRaises(ValueError):
            c7.payload_echo(20, 20)

    def test_cardinality_deduplicates_and_partitions(self):
        rows = [tcp(0), tcp(.1), tcp(.3, dport=22), tcp(.4, dst="192.168.50.30"), tcp(1)]
        groups = c8.cardinalidad(rows)
        key = (0, "192.168.50.10", "192.168.50.20")
        self.assertEqual(groups[key]["syn"], 3)
        self.assertEqual(groups[key]["ports"], {80, 22})
        self.assertEqual(len(groups), 3)
        self.assertIn((3, "192.168.50.10", "192.168.50.20"), c8.cardinalidad([tcp(.3)], .1))

    def test_rules_scoped_no_general_drop(self):
        for name in ("caso01-regla.nft", "caso07-regla-icmp.nft", "caso08-regla-portscan.nft"):
            text = (c1.CASOS / name).read_text(encoding="utf-8")
            code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
            self.assertIn("policy accept", code)
            self.assertNotIn("policy drop", code)
            self.assertNotIn("forward", code)
            self.assertIn("192.168.50.20", code)
            if name.startswith("caso08"):
                self.assertLess(code.index("limit rate"), code.index("log prefix"))
                self.assertNotIn("drop", code)
            else:
                self.assertIn("limit rate over", code)


@unittest.skipUnless(Path(c1.TSHARK).is_file() or shutil.which(c1.TSHARK), "tshark no disponible")
class TestPcapOffline(unittest.TestCase):
    def test_syn_counts_and_correlated_completions(self):
        for name, expected in [("caso01-synflood.pcap", 203), ("caso01-synflood-ratelimit.pcap", 123)]:
            rows = c1.flags(c1.CASOS / name)
            self.assertEqual(c1.clasificar(rows)["SYN"], expected)
            self.assertEqual(sum(a["completed"] is not None for a in c1.handshakes(rows)), 3)
            self.assertEqual(c1.clasificar(rows)["ACK_sin_SYN_FIN_RST"], 15)

    def test_baseline_read_for_tcp_and_icmp(self):
        self.assertGreater(c1.duracion(c1.BASELINE), 290)
        rows = c1.flags(c1.BASELINE, "tcp && ip.addr == 192.168.50.20 && tcp.port == 80")
        self.assertEqual(c1.clasificar(rows)["SYN"], 0)
        self.assertEqual(len(rows), 57)
        echo = c7.leer(c1.BASELINE)
        self.assertEqual(len(echo), 152)
        self.assertEqual({r['payload'] for r in echo}, {32})

    def test_dns_generator_valid_no_malformed_ntp(self):
        pcap = c1.CASOS / "caso06-reflexion-udp.pcap"
        self.assertEqual(c1.campos(pcap, ["frame.number"], "_ws.malformed || ntp"), [])
        dns = c1.campos(pcap, ["dns.flags.response", "dns.qry.type", "dns.qry.class"], "dns")
        normalized = [(qr.lower() in ("1", "true"), int(typ, 0), int(cls, 0)) for qr, typ, cls in dns]
        self.assertEqual(normalized, [(False, 1, 1), (True, 1, 1)])
        self.assertEqual(len(c1.campos(pcap, ["frame.number"], "udp.port == 40000")), 40)

    def test_case02_label_metrics_on_generated_pcap(self):
        queries = c1.campos(c1.CASOS / "caso02-dns-tunneling.pcap", ["dns.qry.name"], "dns.flags.response == 0")
        metrics = [c2.caracteristicas(q[0]) for q in queries]
        self.assertEqual(len(metrics), 37)
        self.assertEqual(sum(c2.sospechosa(length, entropy) for _, length, entropy, _ in metrics), 21)
        self.assertLessEqual(max(m[2] for m in metrics), 4)

    def test_case05_out_of_flow_raw_sequences(self):
        resets = c5.clasificar_resets(c1.flags(c1.CASOS / "caso05-rst.pcap"))
        outside = [row for row, state in resets if state == "fuera de flujo observado"]
        self.assertEqual([r['seq'] for r in outside], [400000, 400100, 400200, 400300])
        self.assertEqual(len(resets), 6)

    def test_case07_generated_payload_sizes(self):
        rows = c7.leer(c1.CASOS / "caso07-icmp.pcap")
        self.assertEqual(len(rows), 63)
        self.assertEqual({r['payload'] for r in rows}, {9, 64, 1289})
        self.assertEqual({r['frame'] for r in rows}, {51, 106, 1331})

    def test_case08_exact_counts(self):
        rows = c1.flags(c1.CASOS / "caso08-portscan.pcap")
        counts = c1.clasificar(rows)
        self.assertEqual((counts['SYN'], counts['SYN_ACK'], counts['RST']), (25, 4, 21))
        syn = [r for r in rows if c1.categoria(r) == "SYN"]
        self.assertEqual(len({r['dport'] for r in syn}), 24)
        self.assertFalse(any(r['dst'] == '192.168.50.30' and r['dport'] == 22 for r in syn))


if __name__ == "__main__":
    unittest.main()
