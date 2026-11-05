"""Пять сценариев задания. Запуск: python test_prototype.py"""
import csv
import os
import secrets
import tempfile
from importlib import import_module

p = import_module("04_прототип")


def prepare(folder):
    # Каждому тесту — чистая память и отдельная папка результатов.
    for data in [p.sites, p.sensors, p.seen, p.critical, p.incidents,
                 p.measurements, p.alerts, p.notifications, p.processed]:
        data.clear()
    p.sites.update(p.load_sites())
    p.OUT_DIR = folder
    p.now = p.get_time({"time": "2025-11-01T08:00:00Z"})
    for user in p.USERS:
        os.environ["SC_TOKEN_" + user.upper()] = secrets.token_hex(32)
    os.environ["SC_KEY_SITE_02_TEMPERATURE"] = secrets.token_hex(32)


def reading(value, minute=0):
    if value != "":
        value = float(value)
    row = {"event_id": "evt_" + secrets.token_hex(8),
           "time": f"2025-11-01T08:{minute:02d}:00Z", "location": "site_02",
           "indicator": "temperature", "value": value}
    catalog = row.copy()
    catalog.update({"norm_min": 20, "norm_max": 26})
    p.sensors.setdefault("site_02/temperature", {"row": catalog, "last": p.now, "stale": False})
    row["signature"] = p.signature(row)
    return row


def test_1():
    dispatcher = os.environ["SC_TOKEN_DISPATCHER_1"]
    incident, error = p.create_incident({"type": "temperature", "location": "site_01"}, dispatcher)
    assert error is None and incident["incident_id"] == "inc_001" and incident["status"] == "NEW"
    assert p.transition_incident(incident, "ASSIGNED", dispatcher, "e_101") == (True, None)
    assert incident["status"] == "ASSIGNED" and incident["responsible"] == "e_101"
    audit, error = p.view_data(dispatcher, "audit")
    assert len(audit) == 2
    assert audit[0]["action"] == "incident_created" and audit[1]["action"] == "incident_assigned"


def test_2():
    assert p.check_indicator(reading("28.3")) == ("WARNING", "ALERT_CREATED")
    p.save_results()
    with open(os.path.join(p.OUT_DIR, "alerts_out.csv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1 and rows[0]["severity"] == "WARNING"
    # Неверные поля отклоняются, даже если подпись корректна.
    for field, value in [("event_id", "wrong"), ("value", "28.3"),
                         ("value", True), ("extra", 1), ("time", "wrong")]:
        packet = reading("28.3")
        packet[field] = value
        packet["signature"] = p.signature(packet)
        result = p.check_indicator(packet)
        assert result[0] == "ERROR" and result[1]["error_code"] == "VALIDATION_ERROR"
    packet = reading("28.3")
    packet["value"] = 40
    assert p.check_indicator(packet)[1]["error_code"] == "SENSOR_SIGNATURE_INVALID"


def test_3():
    token = os.environ["SC_TOKEN_DISPATCHER_1"]
    for location in ["", "site_99"]:
        incident, error = p.create_incident({"location": location}, token)
        assert incident is None and error["error_code"] == "VALIDATION_ERROR"
        assert error["details"] == {"field": "location", "code": "UNKNOWN_LOCATION"}
        assert error["retryable"] is False
        print("422", error)
    assert p.get_user("неверный_токен") == ""
    assert len(p.incidents) == 0


def test_4():
    assert p.check_indicator(reading("28.3")) == ("WARNING", "ALERT_CREATED")
    assert p.check_indicator(reading("28.3", 3)) == ("DUPLICATE", "IGNORED")
    p.save_results()
    with open(os.path.join(p.OUT_DIR, "alerts_out.csv"), encoding="utf-8") as f:
        assert len(list(csv.DictReader(f))) == 1


def test_5():
    assert p.check_indicator(reading(""), csv_input=True) == ("STALE", "ESCALATED")
    p.save_results()
    with open(os.path.join(p.OUT_DIR, "alerts_out.csv"), encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1 and rows[0]["severity"] == "STALE" and rows[0]["action"] == "ESCALATED"
    inbox, error = p.view_data(os.environ["SC_TOKEN_MANAGER_1"], "inbox")
    assert len(inbox) == 1 and inbox[0]["message"] == "STALE"


if __name__ == "__main__":
    base = os.path.dirname(os.path.abspath(__file__))
    with tempfile.TemporaryDirectory(dir=base) as folder:
        for number, test in enumerate([test_1, test_2, test_3, test_4, test_5], 1):
            prepare(os.path.join(folder, str(number)))
            test()
            print("T4-" + str(number) + ": ПРОЙДЕН")
    print("Все пять сценариев пройдены")
