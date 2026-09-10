"""Standalone worker script, run as a genuine separate OS process by
test_state_store_cross_process.py, to prove StateStore's cross-process file
lock actually provides mutual exclusion between two real processes -- not
just two objects/threads inside one process (which is all the in-process
test can prove on its own).

Usage: python _cross_process_lock_worker.py <state_path> <key_prefix> <count>
Writes <count> distinct keys (key_prefix_0 .. key_prefix_<count-1>) to the
shared state file via StateStore.update(), one at a time.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from state_store import StateStore  # noqa: E402


def main():
    state_path, key_prefix, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    store = StateStore(state_path)
    for i in range(count):
        key = f"{key_prefix}_{i}"
        store.update(lambda d, key=key, i=i: {**d, key: i})


if __name__ == "__main__":
    main()
