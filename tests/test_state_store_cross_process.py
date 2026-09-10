import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import unittest

from state_store import StateStore

WORKER_SCRIPT = str(Path(__file__).resolve().parent / "_cross_process_lock_worker.py")


class TestCrossProcessLocking(unittest.TestCase):
    """PLAN.md/review finding: popup_app.py constructs its OWN StateStore
    instance pointed at the same file main.py's daemon uses. StateStore's
    threading.Lock only protects callers sharing one instance -- two
    separate instances (standing in here for two separate processes, e.g.
    the daemon and the popup) previously had zero coordination and could
    silently lose one of two concurrent writes. This simulates that with
    two independent StateStore objects on the same file, hammered from many
    threads, and checks no write is lost."""

    def test_two_independent_store_instances_on_same_file_dont_lose_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "state.json")
            store_a = StateStore(path)  # stands in for main.py's daemon
            store_b = StateStore(path)  # stands in for popup_app.py

            def writer(store, n):
                store.update(lambda d: {**d, f"key_{n}": n})

            threads = []
            for i in range(40):
                store = store_a if i % 2 == 0 else store_b
                threads.append(threading.Thread(target=writer, args=(store, i)))
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            data = store_a.read()
            for i in range(40):
                self.assertEqual(data.get(f"key_{i}"), i, f"write for key_{i} was lost across store instances")

    def test_a_popup_style_clear_does_not_resurrect_a_daemon_consumed_challenge(self):
        # The concrete scenario from the review finding: the popup clears a
        # pending challenge for a DIFFERENT sender/slot while the daemon
        # concurrently consumes one -- neither instance's write should ever
        # be silently dropped by the other's.
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "state.json")
            daemon_store = StateStore(path)
            popup_store = StateStore(path)

            daemon_store.update(
                lambda d: {
                    **d,
                    "pending_challenges": {
                        "owner@example.com": {
                            "type": "login", "prefix": "a b", "suffix": "x",
                            "issued_at": 0, "expires_at": 9e18, "consumed": False, "answered": False,
                        }
                    },
                }
            )

            def daemon_consume():
                def mutate(data):
                    data["pending_challenges"]["owner@example.com"]["consumed"] = True
                    return data

                daemon_store.update(mutate)

            def popup_clear_other_sender():
                def mutate(data):
                    data.setdefault("pending_challenges", {}).pop("someone-else@example.com", None)
                    return data

                popup_store.update(mutate)

            t1 = threading.Thread(target=daemon_consume)
            t2 = threading.Thread(target=popup_clear_other_sender)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

            final = daemon_store.read()
            self.assertTrue(final["pending_challenges"]["owner@example.com"]["consumed"])


class TestGenuineTwoProcessLocking(unittest.TestCase):
    """The tests above prove mutual exclusion across two StateStore
    INSTANCES/threads within one process -- a reasonable analogy, but not
    literal proof that msvcrt.locking actually blocks a second, independent
    OS PROCESS the way popup_app.py (a separate `python popup_app.py`
    invocation) and main.py's daemon actually are. This spawns two genuine
    child processes (via subprocess.Popen, not threading.Thread) hammering
    the same state file concurrently and checks that neither's writes are
    silently lost -- closing that specific gap."""

    def test_two_real_subprocesses_writing_concurrently_lose_no_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = str(Path(tmp) / "state.json")
            StateStore(state_path)  # ensure the file exists before both children race to create it

            count = 25
            proc_a = subprocess.Popen(
                [sys.executable, WORKER_SCRIPT, state_path, "a", str(count)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            proc_b = subprocess.Popen(
                [sys.executable, WORKER_SCRIPT, state_path, "b", str(count)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )

            out_a, _ = proc_a.communicate(timeout=60)
            out_b, _ = proc_b.communicate(timeout=60)

            self.assertEqual(proc_a.returncode, 0, f"worker A failed:\n{out_a}")
            self.assertEqual(proc_b.returncode, 0, f"worker B failed:\n{out_b}")

            data = StateStore(state_path).read()
            for i in range(count):
                self.assertEqual(data.get(f"a_{i}"), i, f"process A's write for a_{i} was lost")
                self.assertEqual(data.get(f"b_{i}"), i, f"process B's write for b_{i} was lost")


if __name__ == "__main__":
    unittest.main()
