from __future__ import annotations

import sqlite3
from typing import Any

from app.core.clock import Clock, SystemClock, to_storage
from app.core.errors import ConflictError, ValidationError
from app.core.security import request_fingerprint
from app.forensics.repository import ForensicRepository, record

QUANTITY_RESOLUTION = 1e-6
# 对整条谱系而言属于“材料离开谱系”的流水；分取是谱系内部转移，不计入。
EXTERNAL_MOVEMENTS = ("取样", "领用", "归还", "报废", "盘点调整")


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
        if data.get("parent_specimen_id"):
            return self._create_aliquot(data)
        return self._create_intake(data)

    def _create_intake(self, data: dict[str, Any]) -> dict[str, Any]:
        """普通到案检材：经原入口登记，数量即为初始可用量，与来源检材无关。"""
        forensic_case = self.repository.require_forensic_case(int(data["case_id"]))
        if forensic_case["status"] not in {"accepted", "restricted", "quarantine"}:
            raise ConflictError("案件尚未受理，不能登记检材")
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

    def _create_aliquot(self, data: dict[str, Any]) -> dict[str, Any]:
        """带来源检材的登记只能是一次原子分取：校验、扣减、立谱在同一事务内完成。"""
        parent_id = int(data["parent_specimen_id"])
        missing = [
            name for name in ("expected_parent_version", "idempotency_key", "business_reason")
            if data.get(name) is None
        ]
        if missing:
            raise ValidationError(f"带来源检材的分取登记必须提供：{','.join(missing)}")
        key = str(data["idempotency_key"]).strip()
        reason = str(data["business_reason"]).strip()
        expected_version = int(data["expected_parent_version"])
        quantity = round(float(data["initial_quantity"]), 6)
        if quantity <= 0:
            raise ValidationError("分取数量必须为正数")
        if not reason:
            raise ValidationError("分取登记必须填写业务理由")

        # 同业务键重试：请求一致则返回最初子检材，内容变化明确报冲突。
        existing = self.repository.aliquot_by_key(key)
        if existing is not None:
            if existing["request_hash"] != request_fingerprint(data):
                raise ConflictError("同一业务键对应了不同的分取请求", context={"child_specimen_id": existing["child_specimen_id"]})
            return self.repository.specimen_detail(int(existing["child_specimen_id"]))

        parent = self.repository.require_specimen(parent_id)
        if int(parent["case_id"]) != int(data["case_id"]):
            raise ValidationError("子检材必须与来源检材属于同一案件")
        if parent["status"] in {"depleted", "disposed"}:
            raise ConflictError("来源检材已经耗尽或销毁，不能分取")
        if parent["status"] == "held" or self.repository.active_holds(parent_id):
            raise ConflictError("来源检材处于冻结状态，不能分取", context={
                "holds": [item["id"] for item in self.repository.active_holds(parent_id)]
            })
        if int(parent["version"]) != expected_version:
            raise ConflictError("来源检材版本冲突", context={"current_version": parent["version"]})
        if quantity > float(parent["available_quantity"]) + QUANTITY_RESOLUTION:
            raise ConflictError("分取数量超过来源检材可用数量", context={
                "requested_grams": quantity,
                "available_grams": float(parent["available_quantity"]),
            })

        timestamp = to_storage(self.clock.now())
        before = round(float(parent["available_quantity"]), 6)
        after = round(before - quantity, 6)
        parent_status = "depleted" if after <= QUANTITY_RESOLUTION else parent["status"]
        try:
            child_cursor = self.connection.execute(
                "INSERT INTO specimens(specimen_no,case_id,parent_specimen_id,received_year,initial_quantity,"
                "available_quantity,integrity_percent,packaging,sealed_on,status,created_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?,?)",
                (
                    data["specimen_no"], data["case_id"], parent_id, data["received_year"],
                    quantity, quantity, data.get("integrity_percent"),
                    data.get("packaging", ""), data.get("sealed_on"), data["created_by"], timestamp, timestamp,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("检材编号已经存在") from exc
        child_id = int(child_cursor.lastrowid)

        try:
            updated = self.connection.execute(
                "UPDATE specimens SET available_quantity=?,status=?,version=version+1,updated_at=? "
                "WHERE id=? AND version=? AND available_quantity>=?",
                (after, parent_status, timestamp, parent_id, expected_version, quantity),
            )
        except sqlite3.IntegrityError:
            raise ConflictError("并发分取导致来源可用量不足")
        if updated.rowcount != 1:
            current = self.repository.require_specimen(parent_id)
            if int(current["version"]) != expected_version:
                raise ConflictError("来源检材版本冲突", context={"current_version": current["version"]})
            raise ConflictError("来源检材可用数量不足", context={"available_grams": current["available_quantity"]})

        self.connection.execute(
            "INSERT INTO custody_events(specimen_id,movement_type,quantity,idempotency_key,actor,reason,created_at) "
            "VALUES(?, '分取', ?, ?, ?, ?, ?)",
            (
                parent_id, -quantity, f"aliquot-parent-{child_id}", data["created_by"],
                f"分取给子检材 {data['specimen_no']}：{reason}", timestamp,
            ),
        )
        self.connection.execute(
            "INSERT INTO custody_events(specimen_id,movement_type,quantity,idempotency_key,actor,reason,created_at) "
            "VALUES(?, '分取', ?, ?, ?, ?, ?)",
            (
                child_id, quantity, f"aliquot-child-{child_id}", data["created_by"],
                f"由来源检材 {parent['specimen_no']} 分取：{reason}", timestamp,
            ),
        )
        self.connection.execute(
            "INSERT INTO specimen_aliquots(parent_specimen_id,child_specimen_id,case_id,quantity,"
            "parent_available_before,parent_available_after,parent_version_before,business_reason,"
            "idempotency_key,request_hash,actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                parent_id, child_id, int(data["case_id"]), quantity, before, after, expected_version,
                reason, key, request_fingerprint(data), data["created_by"], timestamp,
            ),
        )
        return self.repository.specimen_detail(child_id)

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
        """对整条谱系做守恒核对：到案初始量 = 谱系现存可用量 + 离开谱系的外部流水。"""
        root_id = self.repository.lineage_root_id(specimen_id)
        tree_ids = self.repository.lineage_tree_ids(root_id)
        placeholders = ",".join("?" for _ in tree_ids)
        members = [
            record(row) or {}
            for row in self.connection.execute(f"SELECT * FROM specimens WHERE id IN ({placeholders})", tree_ids).fetchall()
        ]
        root = self.repository.require_specimen(root_id)
        movement_clause = ",".join("?" for _ in EXTERNAL_MOVEMENTS)

        external_total = float(self.connection.execute(
            f"SELECT COALESCE(SUM(quantity),0) FROM custody_events WHERE specimen_id IN ({placeholders}) "
            f"AND movement_type IN ({movement_clause})",
            (*tree_ids, *EXTERNAL_MOVEMENTS),
        ).fetchone()[0])
        aliquoted_out = float(self.connection.execute(
            f"SELECT COALESCE(SUM(quantity),0) FROM specimen_aliquots WHERE parent_specimen_id IN ({placeholders})",
            tree_ids,
        ).fetchone()[0])
        child_initial = round(
            sum(float(m["initial_quantity"]) for m in members if int(m["id"]) != root_id), 6
        )

        node_checks: list[dict[str, Any]] = []
        placements_total = 0.0
        placements_ok = True
        for member in members:
            member_id = int(member["id"])
            outgoing = self.repository.aliquots_of_parent(member_id)
            outgoing_total = round(sum(float(item["quantity"]) for item in outgoing), 6)
            node_external = float(self.connection.execute(
                f"SELECT COALESCE(SUM(quantity),0) FROM custody_events WHERE specimen_id=? "
                f"AND movement_type IN ({movement_clause})",
                (member_id, *EXTERNAL_MOVEMENTS),
            ).fetchone()[0])
            node_expected = round(
                float(member["initial_quantity"]) - outgoing_total + node_external, 6
            )
            placed_weight = float(self.connection.execute(
                "SELECT COALESCE(SUM(quantity),0) FROM specimen_placements WHERE specimen_id=? AND removed_at IS NULL",
                (member_id,),
            ).fetchone()[0])
            placements_total += placed_weight
            within = placed_weight <= float(member["available_quantity"]) + 1e-6
            placements_ok = placements_ok and within
            node_checks.append({
                "specimen_id": member_id,
                "specimen_no": member["specimen_no"],
                "parent_specimen_id": member["parent_specimen_id"],
                "recorded_available_grams": round(float(member["available_quantity"]), 6),
                "expected_available_grams": node_expected,
                "available_matches_ledger": abs(float(member["available_quantity"]) - node_expected) < 1e-6,
                "active_placement_grams": round(placed_weight, 6),
                "placements_within_available": within,
            })

        recorded_available = round(sum(float(m["available_quantity"]) for m in members), 6)
        expected_available = round(float(root["initial_quantity"]) + external_total, 6)
        queried = next(item for item in node_checks if item["specimen_id"] == specimen_id)
        return {
            "specimen_id": specimen_id,
            "root_specimen_id": root_id,
            "lineage_specimen_ids": tree_ids,
            "root_initial_grams": round(float(root["initial_quantity"]), 6),
            "recorded_available_grams": queried["recorded_available_grams"],
            "expected_available_grams": queried["expected_available_grams"],
            "active_placement_grams": queried["active_placement_grams"],
            "available_matches_ledger": queried["available_matches_ledger"],
            "placements_within_available": queried["placements_within_available"],
            "lineage": {
                "recorded_available_grams": recorded_available,
                "expected_available_grams": expected_available,
                "active_placement_grams": round(placements_total, 6),
                "aliquoted_grams": round(aliquoted_out, 6),
                "child_initial_grams": child_initial,
                "external_movement_grams": round(external_total, 6),
                "lineage_conserved": abs(recorded_available - expected_available) < 1e-6
                and abs(aliquoted_out - child_initial) < 1e-6,
                "placements_within_available": placements_ok,
            },
            "members": node_checks,
        }
