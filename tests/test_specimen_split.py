from __future__ import annotations

import threading

import pytest

from app.core.errors import ConflictError, ValidationError
from app.database import transaction
from app.forensics.service import ForensicService

from test_forensics_workflow import create_accepted_forensic_case


def create_source_specimen(service: ForensicService, suffix: str = "S1", quantity: float = 5) -> tuple[dict, dict]:
    forensic_case = create_accepted_forensic_case(service, suffix)
    specimen = service.custody.create_specimen({
        "specimen_no": f"SP-SRC-{suffix}", "case_id": forensic_case["id"], "parent_specimen_id": None,
        "received_year": 2026, "initial_quantity": quantity, "integrity_percent": 100,
        "packaging": "原封证物袋", "sealed_on": "2026-09-30", "created_by": "登记员",
    })
    return forensic_case, specimen


def split_payload(specimen: dict, suffix: str, **overrides) -> dict:
    payload = {
        "specimen_no": f"SP-CHILD-{suffix}",
        "quantity": 3,
        "expected_version": specimen["version"],
        "idempotency_key": f"split-{suffix}-0001",
        "reason": "复核留样",
        "actor": "鉴定人甲",
        "packaging": "新封识袋，封识号 SEAL-1",
        "sealed_on": "2026-10-02",
        "integrity_percent": 100,
        "received_year": None,
    }
    payload.update(overrides)
    return payload


def test_split_deducts_source_and_creates_sealed_child(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case, source = create_source_specimen(service, "A1", quantity=5)
        result = service.custody.split_specimen(source["id"], split_payload(source, "A1"))
        assert result["replayed"] is False
        parent, child, split = result["parent"], result["child"], result["split"]
        assert parent["available_quantity"] == 2
        assert parent["version"] == source["version"] + 1
        assert child["parent_specimen_id"] == source["id"]
        assert child["case_id"] == forensic_case["id"]
        assert child["initial_quantity"] == 3 and child["available_quantity"] == 3
        assert child["received_year"] == source["received_year"]
        assert child["packaging"].startswith("新封识袋") and child["sealed_on"] == "2026-10-02"
        assert split["parent_available_before"] == 5 and split["parent_available_after"] == 2
        assert split["reason"] == "复核留样" and split["actor"] == "鉴定人甲"
        parent_moves = [item for item in parent["movements"] if item["movement_type"] == "分取"]
        assert len(parent_moves) == 1 and parent_moves[0]["quantity"] == -3
        child_moves = [item for item in child["movements"] if item["movement_type"] == "分取"]
        assert len(child_moves) == 1 and "SP-SRC-A1" in child_moves[0]["reason"]
        assert parent["splits"][0]["child_specimen_no"] == child["specimen_no"]
        assert child["origin_split"]["parent_specimen_no"] == source["specimen_no"]
        lots = service.repository.forensic_case_detail(forensic_case["id"])["lots"]
        assert sum(lot["available_quantity"] for lot in lots) == 5


def test_split_beyond_available_is_rejected(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case, source = create_source_specimen(service, "B1", quantity=5)
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], split_payload(source, "B1", quantity=8))
        after = service.repository.specimen_detail(source["id"])
        assert after["available_quantity"] == 5
        assert after["splits"] == []
        lots = service.repository.forensic_case_detail(forensic_case["id"])["lots"]
        assert len(lots) == 1
        assert sum(lot["available_quantity"] for lot in lots) == 5


def test_split_validates_version_holds_and_source_status(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, source = create_source_specimen(service, "V1", quantity=5)
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], split_payload(source, "V1", expected_version=source["version"] + 1))
        hold = service.custody.impose_hold({
            "specimen_id": source["id"], "hold_type": "保全", "reason": "法院证据保全", "actor": "审核员",
        })
        held = service.repository.require_specimen(source["id"])
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], split_payload(held, "V1H"))
        service.custody.release_hold(hold["id"], "审核员", "保全解除")
        fresh = service.repository.require_specimen(source["id"])
        result = service.custody.split_specimen(source["id"], split_payload(fresh, "V1F", quantity=5))
        assert result["parent"]["available_quantity"] == 0
        assert result["parent"]["status"] == "depleted"
        with pytest.raises(ConflictError):
            service.custody.split_specimen(
                source["id"], split_payload(result["parent"], "V1G", quantity=1),
            )


def test_split_rejected_when_case_not_active(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case, source = create_source_specimen(service, "C1", quantity=5)
        service.forensic_cases.transition(forensic_case["id"], {
            "target_status": "retired", "reason": "委托方撤销鉴定", "expected_version": 2, "actor": "审核员",
        })
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], split_payload(source, "C1"))


def test_split_replay_returns_original_child_and_conflicts_on_change(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, source = create_source_specimen(service, "R1", quantity=5)
        payload = split_payload(source, "R1", quantity=2)
        first = service.custody.split_specimen(source["id"], payload)
        replay = service.custody.split_specimen(source["id"], dict(payload))
        assert replay["replayed"] is True
        assert replay["child"]["id"] == first["child"]["id"]
        assert replay["split"]["id"] == first["split"]["id"]
        assert replay["parent"]["available_quantity"] == 3
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], {**payload, "quantity": 1})
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], {**payload, "specimen_no": "SP-CHILD-OTHER"})
        assert service.repository.require_specimen(source["id"])["available_quantity"] == 3
        assert len(service.repository.splits_for_lineage([source["id"]])) == 1


def test_intake_entry_rejects_parent_link(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        forensic_case, source = create_source_specimen(service, "P1", quantity=5)
        with pytest.raises(ValidationError):
            service.custody.create_specimen({
                "specimen_no": "SP-BYPASS-1", "case_id": forensic_case["id"], "parent_specimen_id": source["id"],
                "received_year": 2026, "initial_quantity": 8, "created_by": "登记员",
            })
        normal = service.custody.create_specimen({
            "specimen_no": "SP-NORMAL-1", "case_id": forensic_case["id"], "parent_specimen_id": None,
            "received_year": 2026, "initial_quantity": 8, "created_by": "登记员",
        })
        assert normal["initial_quantity"] == 8 and normal["parent_specimen_id"] is None


def test_reconcile_lineage_conserved_across_members(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, source = create_source_specimen(service, "L1", quantity=5)
        first = service.custody.split_specimen(source["id"], split_payload(source, "L1A"))
        child = first["child"]
        second = service.custody.split_specimen(child["id"], split_payload(child, "L1B", quantity=1))
        grandchild = second["child"]
        service.custody.withdraw({
            "specimen_id": child["id"], "quantity": 1, "movement_type": "取样",
            "idempotency_key": "withdraw-l1-0001", "actor": "检验员", "reason": "首次检验取样",
        })
        for specimen_id in (source["id"], child["id"], grandchild["id"]):
            report = service.custody.reconcile(specimen_id)
            assert report["available_matches_ledger"] is True
            lineage = report["lineage"]
            assert lineage["conserved"] is True
            assert lineage["root_specimen_id"] == source["id"]
            assert lineage["member_count"] == 3
            assert lineage["root_initial_grams"] == 5
            assert lineage["total_available_grams"] == 4
            assert lineage["net_consumed_grams"] == 1
            assert lineage["split_total_grams"] == 4


def test_lineage_survives_downstream_references(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, source = create_source_specimen(service, "M1", quantity=10)
        location = service.custody.create_location({
            "location_code": "VAULT-M1", "facility": "检材保管室", "room": "冷藏区", "rack": "R1", "shelf": "S1",
            "capacity_units": 1000, "reference_value": 4, "humidity_percent": 45,
        })
        payload = split_payload(source, "M1", quantity=4)
        result = service.custody.split_specimen(source["id"], payload)
        child, split_id = result["child"], result["split"]["id"]
        service.custody.place_specimen({
            "specimen_id": child["id"], "location_id": location["id"], "quantity": 4,
            "container_code": "BOX-M1", "idempotency_key": "place-m1-0001", "actor": "保管员",
        })
        protocol = service.examinations.create_protocol({
            "protocol_code": "DNA-M1", "discipline": "法医物证", "observation_target": 100, "checkpoint_count": 1,
            "reference_value": 0.99, "turnaround_days": 14, "conclusion_rule": "位点质量满足复核阈值",
            "created_by": "技术负责人",
        })
        examination = service.examinations.schedule_examination({
            "examination_no": "EX-M1", "specimen_id": child["id"], "protocol_id": protocol["id"],
            "examination_type": "受理初检", "sample_quantity": 1, "scheduled_for": "2026-10-05",
            "requested_by": "检验员", "idempotency_key": "schedule-m1-0001",
        })
        assert examination["specimen"]["id"] == child["id"]
        replay = service.custody.split_specimen(source["id"], dict(payload))
        assert replay["replayed"] is True
        assert replay["child"]["id"] == child["id"]
        assert replay["split"]["id"] == split_id
        with pytest.raises(ConflictError):
            service.custody.split_specimen(source["id"], {**payload, "quantity": 2})
        splits = service.repository.splits_for_lineage([source["id"]])
        assert len(splits) == 1 and splits[0]["id"] == split_id and splits[0]["quantity"] == 4
        assert service.repository.require_specimen(child["id"])["parent_specimen_id"] == source["id"]
        detail = service.repository.specimen_detail(source["id"])
        assert detail["splits"][0]["parent_available_before"] == 10
        assert detail["splits"][0]["parent_available_after"] == 6
        assert detail["splits"][0]["reason"] == "复核留样"
        assert detail["splits"][0]["actor"] == "鉴定人甲"


def test_concurrent_splits_never_overdraw(client):
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        _, source = create_source_specimen(service, "N1", quantity=5)
        source_id = source["id"]
    outcomes: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def attempt(index: int) -> None:
        barrier.wait()
        for _ in range(8):
            try:
                with transaction(immediate=True) as connection:
                    service = ForensicService(connection)
                    current = service.repository.require_specimen(source_id)
                    service.custody.split_specimen(source_id, split_payload(
                        current, f"N1-{index}", quantity=2, idempotency_key=f"split-n1-{index:04d}",
                    ))
                with lock:
                    outcomes.append("ok")
                return
            except ConflictError as exc:
                if "可用数量不足" in exc.message:
                    with lock:
                        outcomes.append("insufficient")
                    return
        with lock:
            outcomes.append("exhausted_retries")

    threads = [threading.Thread(target=attempt, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["insufficient", "insufficient", "ok", "ok"]
    with transaction(immediate=True) as connection:
        service = ForensicService(connection)
        detail = service.repository.specimen_detail(source_id)
        assert detail["available_quantity"] == 1
        assert len(detail["splits"]) == 2
        report = service.custody.reconcile(source_id)
        assert report["lineage"]["conserved"] is True
        assert report["lineage"]["member_count"] == 3


def test_split_api_flow(client, admin):
    headers = admin["headers"]
    agency = client.post("/api/forensics/agencies", headers=headers, json={
        "agency_code": "SPLIT-ORG-1", "agency_name": "市司法鉴定中心", "jurisdiction_code": "CN",
        "contact_address": "司法路 9 号", "restrictions": {},
    })
    assert agency.status_code == 201, agency.text
    forensic_case = client.post("/api/forensics/cases", headers=headers, json={
        "case_no": "SPLIT-CASE-1", "case_name": "毒物含量鉴定", "discipline": "法医毒物",
        "entrusted_matter": "血样毒物分析", "agency_id": agency.json()["id"], "case_source": "委托",
        "accepted_on": "2026-09-28", "passport": {}, "created_by": "登记员",
    })
    assert forensic_case.status_code == 201, forensic_case.text
    accepted = client.post(f"/api/forensics/cases/{forensic_case.json()['id']}/transition", headers=headers, json={
        "target_status": "accepted", "reason": "手续齐全", "expected_version": 1, "actor": "审核员",
    })
    assert accepted.status_code == 200, accepted.text
    source = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "SP-API-SRC-1", "case_id": accepted.json()["id"], "received_year": 2026,
        "initial_quantity": 5, "integrity_percent": 100, "packaging": "原封证物袋", "created_by": "登记员",
    })
    assert source.status_code == 201, source.text
    source_id = source.json()["id"]
    bypass = client.post("/api/forensics/specimens", headers=headers, json={
        "specimen_no": "SP-API-BYPASS", "case_id": accepted.json()["id"], "parent_specimen_id": source_id,
        "received_year": 2026, "initial_quantity": 8, "created_by": "登记员",
    })
    assert bypass.status_code == 422
    over = client.post(f"/api/forensics/specimens/{source_id}/splits", headers=headers, json={
        "specimen_no": "SP-API-CHILD-1", "quantity": 8, "expected_version": 1,
        "idempotency_key": "split-api-0001", "reason": "复核留样", "actor": "鉴定人甲",
        "packaging": "新封识袋", "sealed_on": "2026-10-02",
    })
    assert over.status_code == 409
    created = client.post(f"/api/forensics/specimens/{source_id}/splits", headers=headers, json={
        "specimen_no": "SP-API-CHILD-1", "quantity": 3, "expected_version": 1,
        "idempotency_key": "split-api-0001", "reason": "复核留样", "actor": "鉴定人甲",
        "packaging": "新封识袋", "sealed_on": "2026-10-02",
    })
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["replayed"] is False
    assert body["parent"]["available_quantity"] == 2
    assert body["split"]["parent_available_before"] == 5
    assert body["split"]["parent_available_after"] == 2
    replay = client.post(f"/api/forensics/specimens/{source_id}/splits", headers=headers, json={
        "specimen_no": "SP-API-CHILD-1", "quantity": 3, "expected_version": 1,
        "idempotency_key": "split-api-0001", "reason": "复核留样", "actor": "鉴定人甲",
        "packaging": "新封识袋", "sealed_on": "2026-10-02",
    })
    assert replay.status_code == 201
    assert replay.json()["replayed"] is True
    assert replay.json()["child"]["id"] == body["child"]["id"]
    conflict = client.post(f"/api/forensics/specimens/{source_id}/splits", headers=headers, json={
        "specimen_no": "SP-API-CHILD-1", "quantity": 2, "expected_version": 1,
        "idempotency_key": "split-api-0001", "reason": "复核留样", "actor": "鉴定人甲",
        "packaging": "新封识袋", "sealed_on": "2026-10-02",
    })
    assert conflict.status_code == 409
    detail = client.get(f"/api/forensics/specimens/{source_id}", headers=headers).json()
    assert detail["splits"][0]["reason"] == "复核留样"
    assert detail["splits"][0]["actor"] == "鉴定人甲"
    assert detail["splits"][0]["parent_available_before"] == 5
    assert detail["splits"][0]["parent_available_after"] == 2
    child_detail = client.get(f"/api/forensics/specimens/{body['child']['id']}", headers=headers).json()
    assert child_detail["origin_split"]["parent_specimen_no"] == "SP-API-SRC-1"
    assert child_detail["origin_split"]["quantity"] == 3
    for specimen_id in (source_id, body["child"]["id"]):
        recon = client.get(f"/api/forensics/specimens/{specimen_id}/reconcile", headers=headers).json()
        assert recon["lineage"]["conserved"] is True
        assert recon["lineage"]["root_specimen_id"] == source_id
        assert recon["lineage"]["total_available_grams"] == 5
