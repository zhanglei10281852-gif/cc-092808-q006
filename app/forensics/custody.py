from __future__ import annotations

import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.core.security import request_fingerprint
from app.forensics.repository import ForensicRepository, record, records

LEDGER_MOVEMENT_TYPES = ("取样", "领用", "报废", "归还", "盘点调整", "分取")
CONSUMPTION_MOVEMENT_TYPES = ("取样", "领用", "报废", "归还", "盘点调整")


def _movement_clause(movement_types: tuple[str, ...]) -> str:
    return ",".join(f"'{item}'" for item in movement_types)


class CustodyService:
    def __init__(self, connection: sqlite3.Connection, clock: Clock | None = None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        self.repository = ForensicRepository(connection)

    def create_location(self, data: dict[str, Any]) -> dict[str, Any]:
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO storage_locations(location_code,facility,room,rack,shelf,capacity_units,reference_value,"
                "humidity_percent,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    data["location_code"], data["facility"], data["room"], data["rack"], data["shelf"],
                    data["capacity_units"], data["reference_value"], data["humidity_percent"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("库位编码已经存在") from exc
        return self.repository.location_detail(int(cursor.lastrowid))

    def change_location_status(self, location_id: int, status: str, expected_version: int) -> dict[str, Any]:
        if status not in {"active", "maintenance", "closed"}:
            raise ValidationError("库位状态无效")
        before = self.repository.require_location(location_id)
        if int(before["version"]) != expected_version:
            raise ConflictError("库位版本冲突", context={"current_version": before["version"]})
        if status == "closed" and self.repository.location_usage(location_id) > 0:
            raise ConflictError("库位中仍有检材容器，不能关闭")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE storage_locations SET status=?,version=version+1,updated_at=? WHERE id=? AND version=?",
            (status, timestamp, location_id, expected_version),
        )
        return self.repository.location_detail(location_id)

    def create_specimen(self, data: dict[str, Any]) -> dict[str, Any]:
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        if forensic_case["status"] not in {"accepted", "restricted", "quarantine"}:
            raise ConflictError("案件尚未受理，不能登记检材")
        if data.get("parent_specimen_id"):
            raise ValidationError("带来源检材必须通过分取接口原子登记，不能借父标识绕过数量守恒")
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO specimens(specimen_no,case_id,parent_specimen_id,received_year,initial_quantity,"
                "available_quantity,integrity_percent,packaging,sealed_on,status,created_by,created_at,updated_at) "
                "VALUES(?,?,NULL,?,?,?,?,?,?,'pending',?,?,?)",
                (
                    data["specimen_no"], data["case_id"], data["received_year"],
                    data["initial_quantity"], data["initial_quantity"], data.get("integrity_percent"),
                    data.get("packaging", ""), data.get("sealed_on"), data["created_by"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("检材编号已经存在") from exc
        return self.repository.specimen_detail(int(cursor.lastrowid))

    def split_specimen(self, parent_id: int, data: dict[str, Any]) -> dict[str, Any]:
        parent = self.repository.require_specimen(parent_id)
        payload = {
            "parent_specimen_id": int(parent["id"]),
            "specimen_no": data["specimen_no"],
            "quantity": float(data["quantity"]),
            "expected_version": int(data["expected_version"]),
            "reason": data["reason"],
            "actor": data["actor"],
            "packaging": data["packaging"],
            "sealed_on": data["sealed_on"],
            "integrity_percent": data.get("integrity_percent"),
            "received_year": data.get("received_year") or int(parent["received_year"]),
        }
        fingerprint = request_fingerprint(payload)
        existing = self.repository.split_by_key(data["idempotency_key"])
        if existing:
            if existing["request_hash"] != fingerprint:
                raise ConflictError("同一分取业务键对应了不同的请求内容", context={"split_id": existing["id"]})
            return self._split_result(existing, replayed=True)
        forensic_case = self.repository.require_forensic_case(int(parent["case_id"]))
        if forensic_case["status"] not in {"accepted", "restricted", "quarantine"}:
            raise ConflictError("案件当前状态不允许分取检材")
        if parent["status"] in {"depleted", "disposed"}:
            raise ConflictError("来源检材已经耗尽或销毁，不能分取")
        holds = self.repository.active_holds(int(parent["id"]))
        if holds:
            raise ConflictError("来源检材存在未解除的保全、质量或权限冻结", context={"holds": [item["id"] for item in holds]})
        quantity = float(data["quantity"])
        available = float(parent["available_quantity"])
        if quantity > available + 1e-9:
            raise ConflictError("来源检材可用数量不足", context={"available_quantity": available})
        if int(parent["version"]) != int(data["expected_version"]):
            raise ConflictError("来源检材版本冲突", context={"current_version": parent["version"]})
        if self.connection.execute(
            "SELECT 1 FROM specimens WHERE specimen_no=?", (data["specimen_no"],)
        ).fetchone():
            raise ConflictError("检材编号已经存在")
        timestamp = to_storage(self.clock.now())
        remaining = round(available - quantity, 6)
        status = "depleted" if remaining <= 1e-9 else parent["status"]
        updated = self.connection.execute(
            "UPDATE specimens SET available_quantity=?,status=?,version=version+1,updated_at=? "
            "WHERE id=? AND version=? AND available_quantity>=?",
            (remaining, status, timestamp, parent["id"], data["expected_version"], quantity),
        )
        if updated.rowcount != 1:
            raise ConflictError("来源检材版本冲突或可用数量不足")
        try:
            cursor = self.connection.execute(
                "INSERT INTO specimens(specimen_no,case_id,parent_specimen_id,received_year,initial_quantity,"
                "available_quantity,integrity_percent,packaging,sealed_on,status,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?,?)",
                (
                    data["specimen_no"], parent["case_id"], parent["id"], payload["received_year"], quantity, quantity,
                    data.get("integrity_percent"), data["packaging"], data["sealed_on"], data["actor"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("检材编号已经存在") from exc
        child_id = int(cursor.lastrowid)
        try:
            split_cursor = self.connection.execute(
                "INSERT INTO specimen_splits(split_key,request_hash,case_id,parent_specimen_id,child_specimen_id,quantity,"
                "parent_available_before,parent_available_after,reason,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    data["idempotency_key"], fingerprint, parent["case_id"], parent["id"], child_id, quantity,
                    available, remaining, data["reason"], data["actor"], timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("分取业务键已经存在") from exc
        self.connection.execute(
            "INSERT INTO custody_events(specimen_id,movement_type,quantity,idempotency_key,actor,reason,created_at) "
            "VALUES(?,'分取',?,?,?,?,?)",
            (parent["id"], -quantity, f"{data['idempotency_key']}:parent", data["actor"], data["reason"], timestamp),
        )
        self.connection.execute(
            "INSERT INTO custody_events(specimen_id,movement_type,quantity,idempotency_key,actor,reason,created_at) "
            "VALUES(?,'分取',0,?,?,?,?)",
            (
                child_id, f"{data['idempotency_key']}:child", data["actor"],
                f"自来源检材 {parent['specimen_no']} 分取建立新封识", timestamp,
            ),
        )
        split = record(self.connection.execute(
            "SELECT * FROM specimen_splits WHERE id=?", (int(split_cursor.lastrowid),)
        ).fetchone())
        return self._split_result(split or {}, replayed=False)

    def _split_result(self, split: dict[str, Any], *, replayed: bool) -> dict[str, Any]:
        return {
            "split": split,
            "parent": self.repository.specimen_detail(int(split["parent_specimen_id"])),
            "child": self.repository.specimen_detail(int(split["child_specimen_id"])),
            "replayed": replayed,
        }

    def place_specimen(self, data: dict[str, Any]) -> dict[str, Any]:
        previous = self.repository.custody_event_by_key(data["idempotency_key"])
        if previous:
            placement = self.repository.require_placement(int(previous["placement_id"]))
            return {"placement": placement, "replayed": True}
        specimen = self.repository.require_specimen(int(data["specimen_id"]))
        location = self.repository.require_location(int(data["location_id"]))
        if specimen["status"] in {"depleted", "disposed"}:
            raise ConflictError("检材已经耗尽或销毁")
        if location["status"] != "active":
            raise ConflictError("目标库位当前不可用")
        active_weight = float(self.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) FROM specimen_placements WHERE specimen_id=? AND removed_at IS NULL",
            (specimen["id"],),
        ).fetchone()[0])
        if active_weight + float(data["quantity"]) > float(specimen["available_quantity"]) + 1e-9:
            raise ValidationError("摆放数量超过检材可用数量")
        used = self.repository.location_usage(int(location["id"]))
        if used + float(data["quantity"]) > float(location["capacity_units"]) + 1e-9:
            raise ConflictError("目标库位容量不足", context={"available_grams": location["capacity_units"] - used})
        timestamp = to_storage(self.clock.now())
        try:
            cursor = self.connection.execute(
                "INSERT INTO specimen_placements(specimen_id,location_id,quantity,container_code,placed_at) VALUES(?,?,?,?,?)",
                (specimen["id"], location["id"], data["quantity"], data["container_code"], timestamp),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("容器编码与入库时间冲突") from exc
        placement_id = int(cursor.lastrowid)
        self.connection.execute(
            "INSERT INTO custody_events(specimen_id,placement_id,movement_type,quantity,to_location_id,idempotency_key,"
            "actor,reason,created_at) VALUES(?,?,'入库',?,?,?,?,?,?)",
            (specimen["id"], placement_id, data["quantity"], location["id"], data["idempotency_key"], data["actor"], "首次入库", timestamp),
        )
        self.connection.execute(
            "UPDATE specimens SET status='stored',version=version+1,updated_at=? WHERE id=?",
            (timestamp, specimen["id"]),
        )
        return {"placement": self.repository.require_placement(placement_id), "replayed": False}

    def move_placement(self, placement_id: int, data: dict[str, Any]) -> dict[str, Any]:
        previous = self.repository.custody_event_by_key(data["idempotency_key"])
        if previous:
            return {"placement": self.repository.require_placement(int(previous["placement_id"])), "replayed": True}
        placement = self.repository.require_placement(placement_id)
        if placement["removed_at"]:
            raise ConflictError("容器已经移出原库位")
        if int(placement["version"]) != int(data["expected_version"]):
            raise ConflictError("容器摆放版本冲突", context={"current_version": placement["version"]})
        target = self.repository.require_location(int(data["target_location_id"]))
        if target["status"] != "active":
            raise ConflictError("目标库位当前不可用")
        used = self.repository.location_usage(int(target["id"]))
        if used + float(placement["quantity"]) > float(target["capacity_units"]) + 1e-9:
            raise ConflictError("目标库位容量不足", context={"available_grams": target["capacity_units"] - used})
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO specimen_placements(specimen_id,location_id,quantity,container_code,placed_at) VALUES(?,?,?,?,?)",
            (placement["specimen_id"], target["id"], placement["quantity"], placement["container_code"], timestamp),
        )
        new_id = int(cursor.lastrowid)
        updated = self.connection.execute(
            "UPDATE specimen_placements SET removed_at=?,version=version+1 WHERE id=? AND version=? AND removed_at IS NULL",
            (timestamp, placement_id, data["expected_version"]),
        )
        if updated.rowcount != 1:
            raise ConflictError("容器摆放版本冲突")
        self.connection.execute(
            "INSERT INTO custody_events(specimen_id,placement_id,movement_type,quantity,from_location_id,to_location_id,"
            "idempotency_key,actor,reason,created_at) VALUES(?,?,'移库',?,?,?,?,?,?,?)",
            (
                placement["specimen_id"], new_id, placement["quantity"], placement["location_id"], target["id"],
                data["idempotency_key"], data["actor"], data["reason"], timestamp,
            ),
        )
        return {"placement": self.repository.require_placement(new_id), "replayed": False}

    def withdraw(self, data: dict[str, Any]) -> dict[str, Any]:
        previous = self.repository.custody_event_by_key(data["idempotency_key"])
        if previous:
            return {"specimen": self.repository.specimen_detail(int(previous["specimen_id"])), "movement": previous, "replayed": True}
        specimen = self.repository.require_specimen(int(data["specimen_id"]))
        holds = self.repository.active_holds(int(specimen["id"]))
        if holds:
            raise ConflictError("检材存在未解除的保全、质量或权限冻结", context={"holds": [item["id"] for item in holds]})
        quantity = float(data["quantity"])
        if quantity > float(specimen["available_quantity"]) + 1e-9:
            raise ConflictError("检材可用数量不足")
        timestamp = to_storage(self.clock.now())
        remaining = round(float(specimen["available_quantity"]) - quantity, 6)
        status = "depleted" if remaining <= 1e-9 else specimen["status"]
        self.connection.execute(
            "UPDATE specimens SET available_quantity=?,status=?,version=version+1,updated_at=? WHERE id=?",
            (remaining, status, timestamp, specimen["id"]),
        )
        cursor = self.connection.execute(
            "INSERT INTO custody_events(specimen_id,movement_type,quantity,idempotency_key,actor,reason,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (specimen["id"], data["movement_type"], -quantity, data["idempotency_key"], data["actor"], data["reason"], timestamp),
        )
        return {
            "specimen": self.repository.specimen_detail(int(specimen["id"])),
            "movement": record(self.connection.execute("SELECT * FROM custody_events WHERE id=?", (cursor.lastrowid,)).fetchone()),
            "replayed": False,
        }

    def impose_hold(self, data: dict[str, Any]) -> dict[str, Any]:
        specimen = self.repository.require_specimen(int(data["specimen_id"]))
        existing = self.connection.execute(
            "SELECT * FROM specimen_holds WHERE specimen_id=? AND hold_type=? AND released_at IS NULL",
            (specimen["id"], data["hold_type"]),
        ).fetchone()
        if existing:
            raise ConflictError("该类型冻结已经存在")
        timestamp = to_storage(self.clock.now())
        cursor = self.connection.execute(
            "INSERT INTO specimen_holds(specimen_id,hold_type,reason,imposed_by,imposed_at) VALUES(?,?,?,?,?)",
            (specimen["id"], data["hold_type"], data["reason"], data["actor"], timestamp),
        )
        self.connection.execute(
            "UPDATE specimens SET status='held',version=version+1,updated_at=? WHERE id=? AND status NOT IN ('depleted','disposed')",
            (timestamp, specimen["id"]),
        )
        return record(self.connection.execute("SELECT * FROM specimen_holds WHERE id=?", (cursor.lastrowid,)).fetchone()) or {}

    def release_hold(self, hold_id: int, actor: str, reason: str) -> dict[str, Any]:
        hold = record(self.connection.execute("SELECT * FROM specimen_holds WHERE id=?", (hold_id,)).fetchone())
        if not hold:
            raise ValidationError("冻结记录不存在")
        if hold["released_at"]:
            raise ConflictError("冻结记录已经解除")
        timestamp = to_storage(self.clock.now())
        self.connection.execute(
            "UPDATE specimen_holds SET released_by=?,released_at=?,release_reason=? WHERE id=? AND released_at IS NULL",
            (actor, timestamp, reason, hold_id),
        )
        remaining = self.repository.active_holds(int(hold["specimen_id"]))
        if not remaining:
            self.connection.execute(
                "UPDATE specimens SET status=CASE WHEN available_quantity<=0 THEN 'depleted' ELSE 'stored' END,"
                "version=version+1,updated_at=? WHERE id=? AND status='held'",
                (timestamp, hold["specimen_id"]),
            )
        return record(self.connection.execute("SELECT * FROM specimen_holds WHERE id=?", (hold_id,)).fetchone()) or {}

    def reconcile(self, specimen_id: int) -> dict[str, Any]:
        specimen = self.repository.require_specimen(specimen_id)
        movement_total = float(self.connection.execute(
            f"SELECT COALESCE(SUM(quantity),0) FROM custody_events WHERE specimen_id=? "
            f"AND movement_type IN ({_movement_clause(LEDGER_MOVEMENT_TYPES)})",
            (specimen_id,),
        ).fetchone()[0])
        expected_available = round(float(specimen["initial_quantity"]) + movement_total, 6)
        placed_weight = float(self.connection.execute(
            "SELECT COALESCE(SUM(quantity),0) FROM specimen_placements WHERE specimen_id=? AND removed_at IS NULL", (specimen_id,)
        ).fetchone()[0])
        return {
            "specimen_id": specimen_id,
            "recorded_available_grams": specimen["available_quantity"],
            "expected_available_grams": expected_available,
            "active_placement_grams": placed_weight,
            "available_matches_ledger": abs(float(specimen["available_quantity"]) - expected_available) < 1e-6,
            "placements_within_available": placed_weight <= float(specimen["available_quantity"]) + 1e-6,
            "lineage": self._lineage_conservation(specimen),
        }

    def _lineage_conservation(self, specimen: dict[str, Any]) -> dict[str, Any]:
        root = specimen
        seen = {int(root["id"])}
        while root.get("parent_specimen_id"):
            root = self.repository.require_specimen(int(root["parent_specimen_id"]))
            if int(root["id"]) in seen:
                break
            seen.add(int(root["id"]))
        members: list[dict[str, Any]] = []
        queue = [root]
        visited: set[int] = set()
        while queue:
            node = queue.pop()
            if int(node["id"]) in visited:
                continue
            visited.add(int(node["id"]))
            members.append(node)
            queue.extend(records(self.connection.execute(
                "SELECT * FROM specimens WHERE parent_specimen_id=? ORDER BY id", (node["id"],)
            ).fetchall()))
        member_ids = [int(item["id"]) for item in members]
        placeholders = ",".join("?" for _ in member_ids)
        ledger_rows = self.connection.execute(
            f"SELECT specimen_id,COALESCE(SUM(quantity),0) FROM custody_events WHERE specimen_id IN ({placeholders}) "
            f"AND movement_type IN ({_movement_clause(LEDGER_MOVEMENT_TYPES)}) GROUP BY specimen_id",
            member_ids,
        ).fetchall()
        ledger_totals = {int(row[0]): float(row[1]) for row in ledger_rows}
        member_reports: list[dict[str, Any]] = []
        ledgers_match = True
        for item in sorted(members, key=lambda entry: int(entry["id"])):
            expected = round(float(item["initial_quantity"]) + ledger_totals.get(int(item["id"]), 0.0), 6)
            matches = abs(float(item["available_quantity"]) - expected) < 1e-6
            ledgers_match = ledgers_match and matches
            member_reports.append({
                "specimen_id": int(item["id"]),
                "specimen_no": item["specimen_no"],
                "recorded_available_grams": item["available_quantity"],
                "expected_available_grams": expected,
                "available_matches_ledger": matches,
            })
        consumed = float(self.connection.execute(
            f"SELECT COALESCE(SUM(-quantity),0) FROM custody_events WHERE specimen_id IN ({placeholders}) "
            f"AND movement_type IN ({_movement_clause(CONSUMPTION_MOVEMENT_TYPES)})",
            member_ids,
        ).fetchone()[0])
        splits = self.repository.splits_for_lineage(member_ids)
        total_available = round(sum(float(item["available_quantity"]) for item in members), 6)
        root_initial = float(root["initial_quantity"])
        conserved = ledgers_match and abs(root_initial - (total_available + consumed)) < 1e-6
        return {
            "root_specimen_id": int(root["id"]),
            "member_count": len(members),
            "members": member_reports,
            "root_initial_grams": root_initial,
            "total_available_grams": total_available,
            "net_consumed_grams": round(consumed, 6),
            "split_total_grams": round(sum(float(split["quantity"]) for split in splits), 6),
            "conserved": conserved,
        }
