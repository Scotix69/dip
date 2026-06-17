#!/usr/bin/env python3
import argparse
import random
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def write_metric(vm_url: str, vlan: int, bytes_in: int, packets_in: int, flow_id: int) -> None:
    timestamp_ns = int(time.time() * 1_000_000_000)

    line = (
        f'netflow_test,'
        f'vlan_id={vlan},'
        f'src=10.0.{vlan}.{flow_id},'
        f'dst=10.0.{vlan}.254 '
        f'bytes_in={bytes_in}i,'
        f'packets_in={packets_in}i,'
        f'flow_count=1i '
        f'{timestamp_ns}'
    )

    data = line.encode("utf-8")
    url = vm_url.rstrip("/") + "/write"

    request = urllib.request.Request(
        url=url,
        data=data,
        method="POST",
        headers={"Content-Type": "text/plain"},
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        if response.status not in (200, 204):
            raise RuntimeError(f"VictoriaMetrics returned HTTP {response.status}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate test VLAN metrics for VictoriaMetrics.")
    parser.add_argument("--vlan", type=int, default=20)
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--vm-url", default="http://localhost:8428")

    args = parser.parse_args()

    print(f"Sending {args.samples} test samples to {args.vm_url}")
    print(f"VLAN: {args.vlan}")
    print()

    for i in range(args.samples):
        bytes_in = random.randint(20_000, 80_000)
        packets_in = random.randint(200, 800)
        flow_id = random.randint(1, 5)

        write_metric(
            vm_url=args.vm_url,
            vlan=args.vlan,
            bytes_in=bytes_in,
            packets_in=packets_in,
            flow_id=flow_id,
        )

        now = datetime.now(timezone.utc).isoformat()
        print(
            f"[{i + 1}/{args.samples}] "
            f"{now} vlan={args.vlan} "
            f"bytes_in={bytes_in} packets_in={packets_in} flow={flow_id}"
        )

        time.sleep(args.interval)

    print()
    print("Done. Check:")
    print("  http://localhost:8000/tables/vlans")
    print("  http://localhost:8000/tables/summary")
    print("  http://localhost:8000/tables/rates")
    print("  http://localhost:8000/tables/anomalies")


if __name__ == "__main__":
    main()