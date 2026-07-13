#!/usr/bin/env python3

"""
PlutoSDR gzip live mirror

Authoritative:
    *.jsonl.gz

Live mirrors:
    runtime/*_live.jsonl

Purpose:
    Watch growing gzip SDR logs and create live readable streams.
"""

import os
import gzip
import json
import time
import glob
import shutil
import logging
import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = BASE_DIR
RUNTIME_DIR = os.path.join(BASE_DIR, "runtime")

os.makedirs(RUNTIME_DIR, exist_ok=True)


LOG_FILE = os.path.join(
    RUNTIME_DIR,
    "watcher.log"
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(
            LOG_FILE,
            encoding="utf-8"
        ),
        logging.StreamHandler()
    ]
)


STATE = {}
LAST_PROCESS = {}

def state_file(name):

    return os.path.join(
        RUNTIME_DIR,
        name + ".state.json"
    )


def load_state(name):

    path = state_file(name)

    if not os.path.exists(path):
        return {
            "records":0
        }

    with open(path,"r") as f:
        return json.load(f)



def save_state(name,state):

    with open(state_file(name),"w") as f:
        json.dump(
            state,
            f,
            indent=2
        )



def mirror_name(src):

    base=os.path.basename(src)

    if base.startswith("sweep_"):
        return "sweep_live.jsonl"

    if base.startswith("iq_"):
        return "iq_live.jsonl"

    return None


def process_gzip(path):

    target = mirror_name(path)

    if not target:
        return

    now = time.time()

    if path in LAST_PROCESS:
        if now - LAST_PROCESS[path] < 0.25:
            return

    LAST_PROCESS[path] = now

    name = os.path.splitext(
        os.path.basename(path)
    )[0]

    out = os.path.join(
        RUNTIME_DIR,
        target
    )

    state = load_state(name)

    processed = state.get(
        "records",
        0
    )

    new_records = []

    try:

        with gzip.open(
            path,
            "rt",
            errors="ignore"
        ) as gz:

            for idx, line in enumerate(gz):

                if idx < processed:
                    continue

                if line.strip():
                    new_records.append(line)


        if new_records:

            with open(
                out,
                "a",
                encoding="utf-8"
            ) as f:

                f.writelines(new_records)


            state["records"] = (
                processed +
                len(new_records)
            )

            save_state(
                name,
                state
            )

            update_live_status(
                os.path.basename(path),
                len(new_records),
                state["records"]
            )

            logging.info(
                "%s +%d records",
                os.path.basename(path),
                len(new_records)
            )


    except EOFError:

        logging.warning(
            "Partial gzip write: %s",
            os.path.basename(path)
        )


    except Exception:

        logging.exception(
            "Failed processing %s",
            path
        )



class GzipWatcher(FileSystemEventHandler):

    def on_modified(self, event):

        if event.is_directory:
            return

        if not event.src_path.endswith(".jsonl.gz"):
            return

        time.sleep(0.15)

        try:
            process_gzip(event.src_path)

        except EOFError:

            logging.warning(
                "Partial gzip write detected: %s",
                event.src_path
            )

        except Exception:

            logging.exception(
                "Watcher processing failure: %s",
                event.src_path
            )

def update_live_status(source, added, total):

    status = {
        "live": True,
        "source": source,
        "added": added,
        "records": total,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

    with open(
        os.path.join(
            RUNTIME_DIR,
            "status.json"
        ),
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            status,
            f,
            indent=2
        )

def initial_scan():

    for f in glob.glob(
        os.path.join(
            LOG_DIR,
            "*.jsonl.gz"
        )
    ):

        process_gzip(f)


if __name__ == "__main__":

    logging.info(
        "PlutoSDR gzip watcher starting"
    )

    print(
        f"Watching: {LOG_DIR}"
    )

    print(
        f"Output: {RUNTIME_DIR}"
    )

    initial_scan()

    observer = Observer()

    observer.schedule(
        GzipWatcher(),
        LOG_DIR,
        recursive=False
    )

    observer.start()

    try:

        while True:
            time.sleep(1)

    except KeyboardInterrupt:

        print("Stopping watcher")

        observer.stop()

    observer.join()