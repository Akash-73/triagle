"""How many alerts a second? A replay, not a promise.

    python -m eval.replay_speed            # about a minute

Replays the Wazuh-shaped labelled set, with new ids and times spread over a
week, three ways:

  1. the rules alone: one batch judged from nothing
  2. the console's intake: batches of 20 arriving into a queue that fills to
     its limit and rolls, the way a forwarder sends them
  3. one alert at a time into the full queue: the slowest way to send

No model is called and no network is used: a verdict never waits on a model.
The figures are for the machine this runs on. They say what one process can
take, which is what one deployment has today.
"""
import copy
import json
import os
import resource
import statistics
import time

os.environ.setdefault("TRIAGLE_AUTH", "off")
os.environ["TRIAGLE_SEED"] = "off"
os.environ.pop("TRIAGLE_STATE_FILE", None)

from app import main                                  # noqa: E402
from app.orchestrator import process_batch            # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CUSTOMER = "Greenvale Co-operative Bank"


def variants(seed, n, start=0):
    out = []
    for i in range(start, start + n):
        raw = copy.deepcopy(seed[i % len(seed)]["raw"])
        raw["id"] = f"18{i:08d}.{i}"
        day, sec = 22 + (i // 2000) % 6, i % 86400
        raw["timestamp"] = f"2026-11-{day:02d}T{sec // 3600:02d}:{sec % 3600 // 60:02d}:{sec % 60:02d}.000+0000"
        out.append({"source": "wazuh", "client": CUSTOMER, "raw": raw})
    return out


def run(batches=200, size=20):
    with open(os.path.join(HERE, "wazuh_dataset.json")) as f:
        seed = json.load(f)
    out = {"cores": os.cpu_count()}

    items = variants(seed, 5000)
    t = time.perf_counter()
    process_batch(items)
    dt = time.perf_counter() - t
    out["rules_per_second"] = round(len(items) / dt)
    out["rules_ms_each"] = round(dt / len(items) * 1000, 2)

    main._CACHE.clear()
    main._load_result()
    took, sent, t0 = [], 0, time.perf_counter()
    for b in range(batches):
        t = time.perf_counter()
        sent += main._add_alerts(variants(seed, size, start=100000 + b * size))
        took.append(time.perf_counter() - t)
    total = time.perf_counter() - t0
    out.update(intake_alerts=sent, intake_per_second=round(sent / total), held=len(main._CACHE["live"]),
               rolled=main._CACHE["rolled"]["total"], batch_ms=round(statistics.median(took[-50:]) * 1000))

    single = []
    for i in range(30):
        t = time.perf_counter()
        main._add_alerts(variants(seed, 1, start=900000 + i))
        single.append(time.perf_counter() - t)
    out["single_ms"] = round(statistics.median(single) * 1000)
    out["single_per_day"] = round(86400 / statistics.median(single))
    out["memory_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024)
    return out


if __name__ == "__main__":
    r = run()
    print(f"On this machine ({r['cores']} cores, one process, no model called):")
    print(f"  The rules alone        {r['rules_per_second']:,} alerts a second, {r['rules_ms_each']} ms each")
    print(f"  The console's intake   {r['intake_per_second']:,} alerts a second in batches of 20 "
          f"({r['intake_alerts']:,} sent, {r['held']:,} held, {r['rolled']:,} rolled off)")
    print(f"  One batch, queue full  {r['batch_ms']} ms")
    print(f"  One alert at a time    {r['single_ms']} ms each, which is {r['single_per_day']:,} a day")
    print(f"  Memory                 {r['memory_mb']} MB")
