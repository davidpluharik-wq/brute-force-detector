import queue
import unittest
from unittest.mock import patch
import brute_force_detector as detector


class BehaviorTests(unittest.TestCase):
    def test_login_alert_can_repeat_after_window(self):
        events = queue.Queue()
        worker = detector.LogTailThread('/unused', events, 10, 2)
        line = 'Failed password for guest from 192.0.2.1 port 22'
        with patch.object(detector.time, 'time', side_effect=[0, 1, 20, 21]):
            for _ in range(4):
                worker._process_line(line)
        alerts = []
        while not events.empty():
            kind, payload = events.get_nowait()
            if kind == 'brute_force_detected':
                alerts.append(payload)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[-1]['count'], 2)
