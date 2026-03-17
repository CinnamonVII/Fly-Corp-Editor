#!/usr/bin/env python3
import gzip
import json
import os
import sys
import time
import argparse
import struct
import re
import subprocess
import threading
from collections import Counter, deque


class FlyCorpAdvisor:
    def __init__(self, file_path, mock=False):
        self.file_path = file_path
        self.mock = mock
        self.pid = None
        self.money_addr = None
        self.money_type = 'int'
        self.last_mtime = 0
        self.data = {}
        self.last_update_str = "Never"
        self.live_money = 0
        self.is_scanning = False
        self.money_history = deque(maxlen=60)  # Bug 10: 60 samples (~1 min window)
        self.income_per_sec = 0
        self.extracted_data = {}
        self.optimizations = []
        self.last_scan_attempt = 0  # Bug 2: time-based retry
        self.ptrace_ok = None  # Bug 5: ptrace check cache

        self.HIGH_WEIGHT = ["USA", "China", "India", "Germany", "France", "United Kingdom", "Japan"]

        # Issue 12: Real unlock costs (approximate from game data)
        self.UNLOCK_COSTS = {
            "USA": 15000,
            "China": 18000,
            "India": 12000,
            "Germany": 10000,
            "France": 8000,
            "United Kingdom": 9000,
            "Japan": 14000,
        }

    # Bug 1: Use pgrep -f to find the game process under Proton/Wine
    def find_pid(self):
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'Fly.Corp'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                for p in pids:
                    p = p.strip()
                    if p:
                        return int(p)
        except Exception:
            pass
        # Fallback: also try the old /proc/comm method
        try:
            pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
            for pid in pids:
                try:
                    with open(f'/proc/{pid}/comm', 'r') as f:
                        if 'Fly Corp' in f.read():
                            return int(pid)
                except Exception:
                    continue
        except Exception:
            pass
        return None

    # Bug 5: Check ptrace_scope and warn user
    def check_ptrace(self):
        if self.ptrace_ok is not None:
            return self.ptrace_ok
        try:
            with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as f:
                scope = int(f.read().strip())
            if scope >= 1:
                print("  ⚠️  WARNING: ptrace_scope is set to 1 (restricted).")
                print("     Live memory reading may fail. To fix:")
                print("     echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope")
                self.ptrace_ok = False
                return False
            self.ptrace_ok = True
            return True
        except Exception:
            self.ptrace_ok = True  # Assume OK if we can't check
            return True

    def _do_scan(self):
        """Background scan worker (Issue 9: non-blocking)"""
        self.is_scanning = True
        gs = self.data.get("GameState", {})
        save_money = gs.get("Money", 0)
        spent = gs.get("TotalInfrastructureSpent", -1)
        if save_money < 100 or spent < 10:
            self.is_scanning = False
            return
        print(f"  [Scanning for struct anchor (Spent: {spent}) in memory...]")
        t_spent = struct.pack('<i', int(spent))
        candidates = []
        try:
            with open(f'/proc/{self.pid}/maps', 'r') as maps:
                mem_f = open(f'/proc/{self.pid}/mem', 'rb')
                for line in maps:
                    if 'rw-p' not in line:
                        continue
                    parts = line.split()
                    addr_range = parts[0].split('-')
                    start, end = int(addr_range[0], 16), int(addr_range[1], 16)
                    size = end - start
                    if size > 120 * 1024 * 1024:
                        continue
                    try:
                        mem_f.seek(start)
                        chunk = mem_f.read(size)
                        for m in re.finditer(re.escape(t_spent), chunk):
                            candidates.append(start + m.start())
                    except Exception:
                        continue
                mem_f.close()
        except Exception:
            pass
        if not candidates:
            print(f"  [No struct anchors found for Spent={spent}]")
            self.is_scanning = False
            return
        print(f"  [Validating {len(candidates)} structural anchors...]")
        valid = []
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                for addr in candidates:
                    try:
                        mem.seek(addr - 336)
                        v = struct.unpack('<d', mem.read(8))[0]
                        # Bug 4: Accept both directions with wide tolerance
                        tolerance = max(10_000_000, save_money * 3)
                        if abs(v - save_money) < tolerance:
                            valid.append((addr - 336, 'double'))
                    except Exception:
                        continue
        except Exception:
            pass
        # Bug 3: Diagnostic logging
        print(f"  [Offset -336 validation: {len(valid)} hits from {len(candidates)} anchors]")
        if valid:
            self.money_addr, self.money_type = valid[-1]
            print(f"  [Live Link Established: {hex(self.money_addr)}]")
        else:
            print(f"  [WARNING: Offset may be wrong for this game version.]")
        self.is_scanning = False

    # Issue 9: Run scan in background thread
    def auto_scan_money(self):
        if self.mock:
            return
        self.pid = self.find_pid()
        if not self.pid:
            return
        self.check_ptrace()
        self.last_scan_attempt = time.time()
        t = threading.Thread(target=self._do_scan, daemon=True)
        t.start()

    def read_live_money(self):
        if self.mock or not self.pid or not self.money_addr:
            return self.data.get("GameState", {}).get("Money", 0)
        try:
            with open(f'/proc/{self.pid}/mem', 'rb', 0) as mem:
                mem.seek(self.money_addr)
                if self.money_type == 'int':
                    return struct.unpack('<i', mem.read(4))[0]
                elif self.money_type == 'float':
                    return int(struct.unpack('<f', mem.read(4))[0])
                elif self.money_type == 'double':
                    return int(struct.unpack('<d', mem.read(8))[0])
                else:
                    return self.data.get("GameState", {}).get("Money", 0)
        except Exception:
            self.money_addr = None
            return self.data.get("GameState", {}).get("Money", 0)

    # Issue 11: Only update last_mtime AFTER successful read
    def load_data(self):
        if self.mock:
            self.data = {"GameState": {"Money": 5000}, "OpenedCountries": [], "Warehouses": [], "Routes": [], "Packages": [], "Planes": []}
            return True
        if not os.path.exists(self.file_path):
            return False
        try:
            mtime = os.path.getmtime(self.file_path)
            if mtime <= self.last_mtime:
                return False
            with gzip.open(self.file_path, 'rb') as f:
                self.data = json.load(f)
            self.last_mtime = mtime  # Only after success
            self.last_update_str = time.strftime('%H:%M:%S')
            self.analyze_flow_data()
            return True
        except Exception:
            # Don't update last_mtime on failure — retry next tick
            return False

    def analyze_flow_data(self):
        raw_warehouses = self.data.get("Warehouses", [])
        raw_routes = self.data.get("Routes", [])
        raw_packages = self.data.get("Packages", [])
        raw_planes = self.data.get("Planes", [])

        warehouses = {w['Id']: {
            'Name': w.get('Name', f"Hub-{w['Id']}"),
            'Country': w.get('AssignedCountryName', '?'),
            'Level': w.get('Level', 1),
            'Capacity': w.get('Level', 1) * 40,
            'Pkgs': len(w.get('PackageIds', [])),
            'TotalProcessed': w.get('TotalPackagesProcessed', 0)
        } for w in raw_warehouses}

        routes = {r['Id']: r for r in raw_routes}
        route_edges = {r['Id']: tuple(sorted((r['OriginWarehouseId'], r['DestinationWarehouseId']))) for r in raw_routes}

        # Bug 7: Build and USE edge_to_routes
        edge_to_routes = {}
        for r_id, edge in route_edges.items():
            if edge not in edge_to_routes:
                edge_to_routes[edge] = []
            edge_to_routes[edge].append(r_id)

        planes = {p['Id']: p for p in raw_planes}
        route_planes = {}
        for p in raw_planes:
            rid = p.get('RouteId')
            if rid not in route_planes:
                route_planes[rid] = []
            route_planes[rid].append(p)

        # Data extraction
        total_backlog = sum(w['Pkgs'] for w in warehouses.values())
        dest_counter = Counter()
        for p in raw_packages:
            d = p.get("DestinationWarehouseId")
            if d in warehouses:
                dest_counter[warehouses[d]['Country']] += 1

        self.extracted_data = {
            "Total Hubs": len(warehouses),
            "Total Routes": len(routes),
            "Total Planes": len(planes),
            "Global Backlog": total_backlog,
            "Top Demand": dest_counter.most_common(3)
        }

        opts = []

        # Bottleneck hubs with throughput context (Bug 8: use TotalProcessed)
        sorted_hubs = sorted(
            [w for w in warehouses.values() if w['Pkgs'] > 0],
            key=lambda w: w['Pkgs'] / w['Capacity'] if w['Capacity'] else 0,
            reverse=True
        )
        for w in sorted_hubs[:3]:
            util = (w['Pkgs'] / w['Capacity']) * 100
            if util > 75:
                throughput = w['TotalProcessed']
                opts.append(
                    f"🚨 BOTTLENECK: {w['Name']} ({w['Country']}) at {util:.0f}% "
                    f"({w['Pkgs']}/{w['Capacity']}), {throughput:,} total processed. Upgrade!"
                )

        # Route waitlist
        route_waitlist = Counter()
        for p in raw_packages:
            path = p.get("DeliveryPathRouteIds", [])
            if path:
                route_waitlist[path[0]] += 1

        # Bug 6: Only flag packages with 3+ hops as genuinely inefficient
        direct_edges = set(route_edges.values())
        indirect_traffic = Counter()
        for p in raw_packages:
            path = p.get("DeliveryPathRouteIds", [])
            if len(path) >= 3:
                o, d = p.get("OriginWarehouseId"), p.get("DestinationWarehouseId")
                if o and d:
                    edge = tuple(sorted((o, d)))
                    indirect_traffic[edge] += 1

        for (a, b), count in indirect_traffic.most_common(3):
            if count >= 5:
                name_a = warehouses.get(a, {}).get('Name', f"Hub-{a}")
                name_b = warehouses.get(b, {}).get('Name', f"Hub-{b}")
                opts.append(f"🛫 LONG TRANSFER: {name_a} ↔ {name_b} has {count} pkgs taking 3+ hops. Consider a direct route!")

        # Bug 7: Use edge_to_routes for stress calc (sum across all routes on an edge)
        for edge, route_ids in edge_to_routes.items():
            all_planes = []
            for r_id in route_ids:
                all_planes.extend(route_planes.get(r_id, []))
            total_cap = sum(p.get('Capacity', 10) for p in all_planes)
            waiting = sum(route_waitlist.get(r_id, 0) for r_id in route_ids)
            a, b = edge
            name_a = warehouses.get(a, {}).get('Name', '?')
            name_b = warehouses.get(b, {}).get('Name', '?')
            if waiting > total_cap * 2 and waiting > 20:
                opts.append(
                    f"⚠️ OVERLOADED: {name_a} ↔ {name_b} has {waiting} pkgs "
                    f"but only {len(all_planes)} plane(s) (cap: {total_cap}). Add planes!"
                )

        # Feature: Hub connectivity score (isolated hubs)
        hub_connections = Counter()
        for r in raw_routes:
            hub_connections[r['OriginWarehouseId']] += 1
            hub_connections[r['DestinationWarehouseId']] += 1
        for hub_id, count in hub_connections.items():
            if count == 1:
                name = warehouses.get(hub_id, {}).get('Name', f'Hub-{hub_id}')
                opts.append(f"🔗 ISOLATED HUB: {name} has only 1 route — single point of failure!")

        # Feature: Idle plane detection
        idle_planes = []
        for p in raw_planes:
            if not p.get('IsFlying', True) and not p.get('IsWaiting', False):
                rid = p.get('RouteId')
                route = routes.get(rid, {})
                o = route.get('OriginWarehouseId')
                d = route.get('DestinationWarehouseId')
                name_o = warehouses.get(o, {}).get('Name', '?')
                name_d = warehouses.get(d, {}).get('Name', '?')
                idle_planes.append(f"{name_o} ↔ {name_d}")
        if idle_planes:
            opts.append(f"💤 IDLE PLANES: {len(idle_planes)} plane(s) sitting idle ({', '.join(idle_planes[:3])})")

        self.optimizations = list(dict.fromkeys(opts))[:12]

    def update_income(self):
        now = time.time()
        self.money_history.append((now, self.live_money))
        if len(self.money_history) > 1:
            dt = self.money_history[-1][0] - self.money_history[0][0]
            dm = self.money_history[-1][1] - self.money_history[0][1]
            if dt > 0:
                self.income_per_sec = dm / dt
            else:
                self.income_per_sec = 0

    def run(self):
        self.load_data()
        self.auto_scan_money()
        try:
            while True:
                save_updated = self.load_data()
                if save_updated:
                    self.auto_scan_money()

                # Bug 2: Time-based retry if scan has failed
                if not self.money_addr and (time.time() - self.last_scan_attempt > 30):
                    self.auto_scan_money()

                new_money = self.read_live_money()
                self.live_money = new_money
                self.update_income()
                os.system('clear')
                print("=== Fly Corp Flow Optimizer (V9 - Full Audit) ===")
                print(f"💰 Money: ${self.live_money:,.0f} | 📈 Live Income: {('+$' if self.income_per_sec >= 0 else '-$')}{abs(self.income_per_sec):,.1f}/sec")
                mem_status = hex(self.money_addr) if self.money_addr else ('Scanning...' if self.is_scanning else 'Not linked')
                print(f"💾 Last Save: {self.last_update_str} | Memory: {mem_status}")
                print("-" * 60)
                if self.is_scanning:
                    print("  [SYSTEM: Scanning memory for live link...]")
                else:
                    # Feature: Cash burn / runway display
                    if self.income_per_sec < -1:
                        runway_secs = self.live_money / abs(self.income_per_sec)
                        print(f"  🔥 CASH BURN: Losing ${abs(self.income_per_sec):.0f}/sec. "
                              f"Funds run out in {runway_secs / 60:.1f}m if unchanged.")

                    # Expansion advice with real costs (Issue 12)
                    opened = self.data.get("OpenedCountries", [])
                    targets = [c for c in self.HIGH_WEIGHT if c not in opened]
                    if targets and self.income_per_sec > 0:
                        target = targets[0]
                        eth = self.UNLOCK_COSTS.get(target, 10000)
                        if self.live_money >= eth:
                            print(f"  🌟 EXPANSION: You can afford {target} (${eth:,})! Unlock now!")
                        elif self.live_money < eth:
                            time_left = (eth - self.live_money) / self.income_per_sec
                            if time_left < 600:
                                print(f"  ⏳ GOAL ETA: {target} (${eth:,}) in ~{time_left / 60:.1f}m at current income.")

                    print("\n📊 EXTRACTED DATA:")
                    if not self.extracted_data:
                        print("  [Waiting for save file data...]")
                    else:
                        for k, v in self.extracted_data.items():
                            if k == "Top Demand":
                                top_str = ", ".join([f"{c} ({cnt})" for c, cnt in v])
                                print(f"  * {k}: {top_str}")
                            else:
                                print(f"  * {k}: {v:,}")

                    print("\n🔧 OPTIMIZATIONS:")
                    if not self.optimizations:
                        print("  ✅ Network is running smoothly!")
                    else:
                        for opt in self.optimizations:
                            print(f"  * {opt}")
                h = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][int(time.time() * 10) % 10]
                print(f"\n[{h}] Live Monitoring... (Ctrl+C to stop)")
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--file")
    args = parser.parse_args()
    default_path = "/home/deck/.local/share/Steam/steamapps/compatdata/1372530/pfx/drive_c/users/steamuser/AppData/LocalLow/KishMish Games/Fly Corp/CargoSaves/save_slot_0.json"
    path = args.file if args.file else default_path
    FlyCorpAdvisor(path).run()