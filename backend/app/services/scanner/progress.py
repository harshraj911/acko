import json
import threading
from collections import defaultdict


class ScanProgress:
    def __init__(self):
        self._condition = threading.Condition()
        self._events: dict[int, list[dict]] = defaultdict(list)
        self._sequence = defaultdict(int)

    def publish(self, progress_key: int, **event):
        with self._condition:
            self._sequence[progress_key] += 1
            record = {"sequence": self._sequence[progress_key], **event}
            self._events[progress_key].append(record)
            self._condition.notify_all()
            return record

    def publish_batch(self, progress_key: int, **event):
        self.publish(-progress_key, **event)

    def after(self, scan_id: int, sequence: int):
        with self._condition:
            return [event for event in self._events.get(scan_id, []) if event["sequence"] > sequence]

    def wait(self, timeout: float):
        with self._condition:
            self._condition.wait(timeout)

    def latest(self, scan_id: int):
        events = self._events.get(scan_id, [])
        return events[-1] if events else None


scan_progress = ScanProgress()
