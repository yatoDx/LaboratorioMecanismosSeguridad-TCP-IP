import unittest

from caso09_siem import correlate, parse, synthetic_events


class SIEMTests(unittest.TestCase):
    def test_disconnect_is_not_connect(self):
        event = parse('Nov 18 20:00:00 c2s1 info Client disconnected: connection closed', 'xmpp', 'prosody')
        self.assertEqual(event['event_type'], 'XMPP_DISCONNECT')

    def test_refused_is_not_attributed(self):
        event = parse('Nov 18 20:00:00 dns dnsmasq[1]: config error is REFUSED', 'dns', 'dnsmasq')
        self.assertEqual(event['src_ip'], '')

    def test_correlation_has_evidence_and_score(self):
        events, records = synthetic_events()
        windows = correlate(events)
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]['score'], 49)
        self.assertEqual(windows[0]['distinct_dst_ports'], 12)
        self.assertEqual(len(windows[0]['evidence_refs']), len(records))
        self.assertEqual(windows[0]['sources'], ['auth', 'nftables', 'nginx'])

    def test_real_and_synthetic_never_merge(self):
        events, _ = synthetic_events()
        real = dict(events[0], evidence_kind='real')
        results = correlate(events + [real])
        self.assertEqual(len(results), 2)
        self.assertFalse(next(r for r in results if r['evidence_kind'] == 'real')['alert'])

    def test_windows_never_merge(self):
        events, _ = synthetic_events()
        changed = dict(events[0], timestamp='2026-11-18T20:31:00-05:00')
        results = correlate(events + [changed])
        self.assertEqual(len(results), 2)

    def test_unknown_line_ignored(self):
        self.assertIsNone(parse('no log record', 'web', 'nginx'))

    def test_http_client_error_not_server_error(self):
        event = parse('192.168.50.10 - - [18/Nov/2026:20:30:00 -0500] "GET / HTTP/1.1" 404 0', 'web', 'nginx')
        self.assertEqual(event['event_type'], 'HTTP_OTHER')


if __name__ == '__main__':
    unittest.main()
