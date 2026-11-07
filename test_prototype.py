"""Пять сценариев и связанные проверки. Запуск: python test_prototype.py"""
import contextlib
import csv
import io
import os
import secrets
import tempfile
from importlib import import_module
from pathlib import Path

p = import_module("04_прототип")


def write(path, fields, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def prepare(folder):
    folder = Path(folder)
    folder.mkdir()
    for variable, name in [
        ("SITES_CSV", "sites.csv"), ("INCIDENTS_CSV", "incidents.csv"),
        ("INDICATORS_CSV", "indicators.csv"), ("OUT_CSV", "alerts_out.csv"),
        ("AUDIT_CSV", "audit_out.csv"), ("AUTO_INCIDENTS_CSV", "auto_incidents_out.csv"),
        ("INCIDENTS_STATE_CSV", "incidents_out.csv"), ("SITES_STATE_CSV", "sites_out.csv"),
        ("MEASUREMENTS_CSV", "measurements_out.csv"), ("INBOX_CSV", "notifications_out.csv"),
    ]:
        setattr(p, variable, str(folder / name))
    p.RUN_INCIDENTS.clear()
    p.USED_IDS.clear()
    p.PROCESSED_EVENTS.clear()
    sites = [
        {"site_id": "site_01", "name": "Участок 1", "zone": "zone_A"},
        {"site_id": "site_02", "name": "Участок 2", "zone": "zone_A"},
        {"site_id": "site_03", "name": "Участок 3", "zone": "zone_B"},
    ]
    write(p.SITES_CSV, ["site_id", "name", "zone"], sites)
    write(p.INCIDENTS_CSV, p.INCIDENT_FIELDS, [])
    write(p.INDICATORS_CSV, list(reading(24)), [reading(24)])
    os.environ["SC_KEY_SITE_02_TEMPERATURE"] = secrets.token_hex(32)


def reading(value, minute=0):
    return {"time": f"2025-11-01T08:{minute:02d}:00Z", "location": "site_02",
            "indicator": "temperature", "value": str(value), "norm_min": "20", "norm_max": "26"}


def run(rows):
    write(p.INDICATORS_CSV, list(reading(24)), rows)
    with contextlib.redirect_stdout(io.StringIO()):
        assert p.main() is None


def test_1():
    sites = p.load_sites()
    data = {"type": "temperature", "location": "site_01", "responsible": "e_101",
            "time": "2025-11-01T08:00:00Z", "status": "NEW"}
    incident, error = p.create_incident(data, sites, "Диспетчер")
    assert error is None and incident["incident_id"] == "inc_001" and incident["status"] == "NEW"
    assert p.transition_incident(incident, "ASSIGNED", "Диспетчер", at="2025-11-01T08:01:00Z") == (True, None)
    assert incident["responsible"] == "e_101"
    audit = p.read_rows(p.AUDIT_CSV)
    assert len(audit) == 2 and [r["action"] for r in audit] == ["created", "assigned"]
    assert all(r["entity_type"] == "incident" for r in audit)
    assert not p.transition_incident(incident, "CLOSED", "Диспетчер")[0]
    assert not p.transition_incident(incident, "IN_PROGRESS", "Инженер", "e_102")[0]
    assert p.transition_incident(incident, "IN_PROGRESS", "Инженер", "e_101")[0]
    assert p.transition_incident(incident, "CLOSED", "Руководитель")[0]
    assert p.read_rows(p.INCIDENTS_STATE_CSV)[0]["status"] == "CLOSED"
    assert not p.transition_incident(incident, "NEW", "Руководитель")[0]
    assert p.create_incident(data, sites, "Администратор")[0] is None
    assert p.create_incident({**data, "location": "site_03"}, sites, "Диспетчер")[0] is None


def test_2():
    run([reading(24), reading(28.3, 1)])
    alerts = p.read_rows(p.OUT_CSV)
    assert len(alerts) == 1 and alerts[0]["severity"] == "WARNING"
    assert p.calc_severity(28.6, 20, 26) == "WARNING"
    event = {"event_id": "evt_abcdef", "time": "2025-11-01T08:02:00Z",
             "location": "site_02", "indicator": "temperature", "value": 28.3}
    event["signature"] = p.signature(event)
    assert p.check_external_indicator(event, p.load_sites(), {}) == [("WARNING", "ALERT_CREATED")]
    changed = {**event, "value": 40}
    assert p.check_external_indicator(changed, p.load_sites(), {}) == [("ERROR", "SENSOR_SIGNATURE_INVALID")]


def test_3():
    for location in ["", "site_99"]:
        incident, error = p.create_incident({"location": location}, p.load_sites(), "Диспетчер")
        assert incident is None and error["error_code"] == "VALIDATION_ERROR"
        assert error["details"] == {"field": "location", "code": "UNKNOWN_LOCATION"}
    assert not p.RUN_INCIDENTS


def test_4():
    seen = {}
    sites = p.load_sites()
    assert p.check_indicator(reading(28.3), sites, seen) == [("WARNING", "ALERT_CREATED")]
    assert p.check_indicator(reading(28.3, 3), sites, seen) == [("DUPLICATE", "IGNORED")]
    run([reading(30), reading(30, 3)])
    assert len(p.read_rows(p.OUT_CSV)) == 1
    auto = p.read_rows(p.AUTO_INCIDENTS_CSV)
    assert len(auto) == 1 and auto[0]["source"] == "auto"
    before = Path(p.AUDIT_CSV).read_bytes()
    run([reading(30), reading(30, 3)])
    assert Path(p.AUDIT_CSV).read_bytes().startswith(before)
    assert len(p.read_rows(p.AUTO_INCIDENTS_CSV)) == 1
    visible, error = p.view_data("Руководитель", "incidents")
    assert error is None and len(visible) == 1


def test_5():
    run([reading("")])
    alerts = p.read_rows(p.OUT_CSV)
    assert len(alerts) == 1 and alerts[0]["severity"] == "STALE" and alerts[0]["action"] == "ESCALATED"
    inbox, error = p.view_data("Руководитель", "inbox")
    assert error is None and len(inbox) == 1 and inbox[0]["message"] == "STALE"
    seen = {}
    sites = p.load_sites()
    p.check_indicator(reading(24), sites, seen)
    assert not p.find_silent_sensors(seen, p.parse_time("2025-11-01T08:05:00Z"))
    assert p.find_silent_sensors(seen, p.parse_time("2025-11-01T08:05:01Z"))
    assert p.view_data("Инженер", "audit", actor_id="e_101")[0] is None


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temporary:
        for number, test in enumerate([test_1, test_2, test_3, test_4, test_5], 1):
            prepare(Path(temporary) / str(number))
            test()
            print(f"T4-{number}: ПРОЙДЕН")
    print("Все пять сценариев и связанные проверки пройдены")
