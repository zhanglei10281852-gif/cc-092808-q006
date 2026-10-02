from __future__ import annotations

import sqlite3

import pytest
from pydantic import ValidationError as PydanticValidationError

from app.core.errors import ConflictError, ValidationError
from app.database import transaction
from app.forensics.schemas import SpecimenCreate
from app.forensics.service import ForensicService
from tests.test_forensics_workflow import create_accepted_forensic_case, create_stored_lot


def _aliquot_payload(specimen_no: str, specimen_id: int, case_id: int, quantity: float, key: str, **overrides) -> dict:
    payload = {
        "specimen_no": specimen_no,
        "case_id": case_id,
        "parent_specimen_id": specimen_id,
        "received_year": 2026,
        "initial_quantity": quantity,
        "integrity_percent": 100,
        "packaging": "复核留样独立封管",
        "sealed_on": "2026-09-10",
        "created_by": "鉴定人甲",
        "expected_parent_version": 2,
        "idempotency_key": key,
        "business_reason": "复核留样 3 份",
    }
    payload.update(overrides)
    return payload


def test_aliquot_atomically_decrements_parent_and_records_lineage(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, parent, _ = create_stored_lot(service, "101")
        # create_stored_lot 入库后版本号已经增加到 2。
        result = service.custody.create_specimen(
            _aliquot_payload("SP-101-A", parent["id"], parent["case_id"], 3, "aliquot-101-0001")
        )
        assert result["available_quantity"] == 3
        assert result["parent_specimen_id"] == parent["id"]

        refreshed_parent = service.repository.specimen_detail(parent["id"])
        assert refreshed_parent["available_quantity"] == 497
        assert refreshed_parent["version"] == 3

        origin = result["aliquot_origin"]
        assert origin["quantity"] == 3
        assert origin["parent_available_before"] == 500
        assert origin["parent_available_after"] == 497
        assert origin["parent_version_before"] == 2
        assert origin["business_reason"] == "复核留样 3 份"
        assert origin["actor"] == "鉴定人甲"
        assert origin["parent"]["specimen_no"] == "SP-101"

        assert refreshed_parent["aliquots"][0]["child"]["specimen_no"] == "SP-101-A"
        movements = {(item["movement_type"], item["quantity"]) for item in refreshed_parent["movements"]}
        assert ("分取", -3.0) in movements
        assert any(
            item["movement_type"] == "分取" and item["quantity"] == 3 for item in result["movements"]
        )

        reconciliation = service.custody.reconcile(result["id"])
        assert reconciliation["lineage"]["lineage_conserved"] is True
        assert reconciliation["lineage"]["recorded_available_grams"] == 500
        assert reconciliation["lineage"]["expected_available_grams"] == 500


def test_aliquot_exceeding_available_is_rejected_and_ledger_unchanged(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_accepted_forensic_case(service, "102")
        specimen = service.custody.create_specimen({
            "specimen_no": "SP-102", "case_id": forensic_case["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 5, "integrity_percent": 100,
            "packaging": "原始封袋", "sealed_on": "2026-09-02", "created_by": "登记员",
        })
        with pytest.raises(ConflictError) as exc_info:
            service.custody.create_specimen(
                _aliquot_payload(
                    "SP-102-A", specimen["id"], forensic_case["id"], 8, "aliquot-102-0001",
                    expected_parent_version=1,
                )
            )
        assert "可用数量" in exc_info.value.message
        parent = service.repository.require_specimen(specimen["id"])
        assert parent["available_quantity"] == 5
        assert service.connection.execute("SELECT COUNT(*) FROM specimens WHERE case_id=?", (forensic_case["id"],)).fetchone()[0] == 1
        assert service.connection.execute("SELECT COUNT(*) FROM specimen_aliquots").fetchone()[0] == 0


def test_aliquot_requires_business_fields(client):
    with pytest.raises(PydanticValidationError):
        SpecimenCreate(
            specimen_no="SP-X-A", case_id=1, parent_specimen_id=1, received_year=2026,
            initial_quantity=1, created_by="鉴定人甲",
        )


def test_same_business_key_replays_original_child_but_changed_payload_conflicts(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, parent, _ = create_stored_lot(service, "103")
        payload = _aliquot_payload("SP-103-A", parent["id"], parent["case_id"], 2, "aliquot-103-0001")
        first = service.custody.create_specimen(payload)
        replay = service.custody.create_specimen(dict(payload))
        assert replay["id"] == first["id"]
        # 父检材只被扣减一次。
        assert service.repository.require_specimen(parent["id"])["available_quantity"] == 498

        changed = _aliquot_payload("SP-103-A", parent["id"], parent["case_id"], 4, "aliquot-103-0001")
        with pytest.raises(ConflictError) as exc_info:
            service.custody.create_specimen(changed)
        assert "不同的分取请求" in exc_info.value.message


def test_aliquot_validates_case_hold_status_and_version(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, parent, _ = create_stored_lot(service, "104")
        other_case = create_accepted_forensic_case(service, "104B")

        with pytest.raises(ValidationError):
            service.custody.create_specimen(
                _aliquot_payload(
                    "SP-104-A", parent["id"], other_case["id"], 1, "aliquot-104-0001",
                    expected_parent_version=2,
                )
            )

        with pytest.raises(ConflictError) as exc_info:
            service.custody.create_specimen(
                _aliquot_payload(
                    "SP-104-A", parent["id"], parent["case_id"], 1, "aliquot-104-0002",
                    expected_parent_version=99,
                )
            )
        assert "版本冲突" in exc_info.value.message

        service.custody.impose_hold({
            "specimen_id": parent["id"], "hold_type": "保全", "reason": "争议待查", "actor": "审核员",
        })
        with pytest.raises(ConflictError):
            service.custody.create_specimen(
                _aliquot_payload(
                    "SP-104-A", parent["id"], parent["case_id"], 1, "aliquot-104-0003",
                    expected_parent_version=3,
                )
            )


def test_concurrent_aliquots_cannot_oversubscribe_parent(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_accepted_forensic_case(service, "105")
        specimen = service.custody.create_specimen({
            "specimen_no": "SP-105", "case_id": forensic_case["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 5, "integrity_percent": 100,
            "packaging": "原始封袋", "sealed_on": "2026-09-02", "created_by": "登记员",
        })
        service.custody.create_specimen(
            _aliquot_payload(
                "SP-105-A", specimen["id"], forensic_case["id"], 3, "aliquot-105-0001",
                expected_parent_version=1,
            )
        )
        # 持有旧版本号的并发分取：版本冲突。
        with pytest.raises(ConflictError):
            service.custody.create_specimen(
                _aliquot_payload(
                    "SP-105-B", specimen["id"], forensic_case["id"], 3, "aliquot-105-0002",
                    expected_parent_version=1,
                )
            )
        # 拿到新版本号后，仅剩 2 份，分取 3 份仍被数量校验拒绝。
        with pytest.raises(ConflictError):
            service.custody.create_specimen(
                _aliquot_payload(
                    "SP-105-B", specimen["id"], forensic_case["id"], 3, "aliquot-105-0003",
                    expected_parent_version=2,
                )
            )
        assert service.repository.require_specimen(specimen["id"])["available_quantity"] == 2
        reconciliation = service.custody.reconcile(specimen["id"])
        assert reconciliation["lineage"]["lineage_conserved"] is True


def test_intake_without_parent_remains_on_original_entry(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case = create_accepted_forensic_case(service, "106")
        specimen = service.custody.create_specimen({
            "specimen_no": "SP-106", "case_id": forensic_case["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 9, "integrity_percent": 100,
            "packaging": "到案原封", "sealed_on": "2026-09-02", "created_by": "登记员",
        })
        assert specimen["parent_specimen_id"] is None
        assert specimen["aliquot_origin"] is None
        assert specimen["available_quantity"] == 9


def test_lineage_history_is_immutable_once_referenced(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, parent, placement = create_stored_lot(service, "107")
        child = service.custody.create_specimen(
            _aliquot_payload("SP-107-A", parent["id"], parent["case_id"], 2, "aliquot-107-0001")
        )
        # 子检材已摆放，模拟后续业务引用。
        location = service.repository.require_location(placement["location_id"])
        service.custody.place_specimen({
            "specimen_id": child["id"], "location_id": location["id"], "quantity": 2,
            "container_code": "BOX-107-A", "idempotency_key": "place-107-0001", "actor": "保管员",
        })
        aliquot_id = connection.execute("SELECT id FROM specimen_aliquots").fetchone()[0]
        blocked = (sqlite3.OperationalError, sqlite3.IntegrityError)
        with pytest.raises(blocked):
            connection.execute("UPDATE specimen_aliquots SET quantity=99 WHERE id=?", (aliquot_id,))
        with pytest.raises(blocked):
            connection.execute("DELETE FROM specimen_aliquots WHERE id=?", (aliquot_id,))
        with pytest.raises(blocked):
            connection.execute(
                "UPDATE specimens SET parent_specimen_id=NULL WHERE id=?", (child["id"],)
            )
        # 被摆放/检验引用的子检材及其谱系均不可删除（外键 RESTRICT + 触发器）。
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM specimens WHERE id=?", (child["id"],))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM specimens WHERE id=?", (parent["id"],))


def test_lineage_conservation_after_downstream_withdrawal(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, parent, _ = create_stored_lot(service, "108")
        child = service.custody.create_specimen(
            _aliquot_payload("SP-108-A", parent["id"], parent["case_id"], 4, "aliquot-108-0001")
        )
        service.custody.withdraw({
            "specimen_id": child["id"], "quantity": 1, "movement_type": "取样",
            "idempotency_key": "withdraw-108-a", "actor": "检验员", "reason": "预实验",
        })
        service.custody.withdraw({
            "specimen_id": parent["id"], "quantity": 6, "movement_type": "领用",
            "idempotency_key": "withdraw-108-b", "actor": "保管员", "reason": "外出比对",
        })
        reconciliation = service.custody.reconcile(parent["id"])
        lineage = reconciliation["lineage"]
        assert lineage["lineage_conserved"] is True
        # 500 = 父剩余 490 + 子剩余 3 + 外部流水 7
        assert lineage["recorded_available_grams"] == 493
        assert lineage["expected_available_grams"] == 493
        assert abs(lineage["external_movement_grams"] - (-7)) < 1e-6
        assert all(item["available_matches_ledger"] for item in reconciliation["members"])


def test_http_aliquot_flow_and_conflict(client, admin):
    headers = admin["headers"]
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "HTTP-ORG-ALQ", "agency_name": "区分局", "jurisdiction_code": "CN",
        "contact_address": "司法路", "restrictions": {},
    })
    assert agency.status_code == 201, agency.text
    case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": "HTTP-CASE-ALQ", "case_name": "分取守恒鉴定", "discipline": "法医物证",
        "entrusted_matter": "留样复核", "agency_id": agency.json()["id"], "case_source": "委托",
        "accepted_on": "2026-09-01", "passport": {}, "created_by": "登记员",
    })
    assert case.status_code == 201, case.text
    accepted = client.post(f"/api/forensics/cases/{case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    intake = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "HTTP-SP-ALQ", "case_id": case.json()["id"], "received_year": 2026,
        "initial_quantity": 5, "integrity_percent": 100, "packaging": "原封", "created_by": "登记员",
    })
    assert intake.status_code == 201, intake.text

    missing = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "HTTP-SP-ALQ-A", "case_id": case.json()["id"],
        "parent_specimen_id": intake.json()["id"], "received_year": 2026,
        "initial_quantity": 2, "created_by": "鉴定人甲",
    })
    assert missing.status_code == 422, missing.text

    aliquot = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "HTTP-SP-ALQ-A", "case_id": case.json()["id"],
        "parent_specimen_id": intake.json()["id"], "received_year": 2026,
        "initial_quantity": 8, "integrity_percent": 100, "packaging": "留样管",
        "created_by": "鉴定人甲", "expected_parent_version": 1,
        "idempotency_key": "http-aliquot-0001", "business_reason": "复核留样",
    })
    assert aliquot.status_code == 409, aliquot.text

    ok = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "HTTP-SP-ALQ-A", "case_id": case.json()["id"],
        "parent_specimen_id": intake.json()["id"], "received_year": 2026,
        "initial_quantity": 3, "integrity_percent": 100, "packaging": "留样管",
        "created_by": "鉴定人甲", "expected_parent_version": 1,
        "idempotency_key": "http-aliquot-0001", "business_reason": "复核留样",
    })
    assert ok.status_code == 201, ok.text
    replay = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "HTTP-SP-ALQ-A", "case_id": case.json()["id"],
        "parent_specimen_id": intake.json()["id"], "received_year": 2026,
        "initial_quantity": 3, "integrity_percent": 100, "packaging": "留样管",
        "created_by": "鉴定人甲", "expected_parent_version": 1,
        "idempotency_key": "http-aliquot-0001", "business_reason": "复核留样",
    })
    assert replay.status_code == 201, replay.text
    assert replay.json()["id"] == ok.json()["id"]

    detail = client.get(f"/api/forensics/specimens/{intake.json()['id']}", headers=headers)
    assert detail.json()["available_quantity"] == 2
    assert detail.json()["aliquots"][0]["business_reason"] == "复核留样"

    reconciliation = client.get(
        f"/api/forensics/specimens/{ok.json()['id']}/reconcile", headers=headers
    )
    assert reconciliation.json()["lineage"]["lineage_conserved"] is True
