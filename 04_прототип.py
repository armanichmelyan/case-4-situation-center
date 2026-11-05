"""Учебный прототип кейса 4. Запуск: python 04_прототип.py"""
import csv
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_CSV = os.path.join(BASE_DIR, "01_данные", "sites.csv")
INCIDENTS_CSV = os.path.join(BASE_DIR, "01_данные", "incidents.csv")
INDICATORS_CSV = os.path.join(BASE_DIR, "01_данные", "indicators.csv")
OUT_DIR = os.path.join(BASE_DIR, "results")
ALLOWED_TRANSITIONS = {
    "NEW": ["ASSIGNED"], "ASSIGNED": ["IN_PROGRESS", "CLOSED"],
    "IN_PROGRESS": ["CLOSED"], "CLOSED": [],
}
SLA = {"WARNING": [60, 240], "CRITICAL": [15, 60], "STALE": [30, 60]}
USERS = {
    "dispatcher_1": {"role": "диспетчер", "zones": ["zone_A"]},
    "dispatcher_2": {"role": "диспетчер", "zones": ["zone_B", "zone_C"]},
    "manager_1": {"role": "руководитель", "zones": ["zone_A", "zone_B", "zone_C"]},
    "e_101": {"role": "инженер", "zones": ["zone_A"]},
    "e_102": {"role": "инженер", "zones": ["zone_A"]},
    "e_103": {"role": "инженер", "zones": ["zone_B"]},
    "e_104": {"role": "инженер", "zones": ["zone_B"]},
    "e_105": {"role": "инженер", "zones": ["zone_C"]},
    "admin_1": {"role": "администратор", "zones": ["zone_A", "zone_B", "zone_C"]},
}
OUT_FIELDS = ["alert_id", "measurement_id", "at", "updated_at", "location", "indicator", "value", "severity", "action"]
INCIDENT_FIELDS = ["incident_id", "type", "location", "time", "responsible", "status", "deadline",
                   "severity", "source", "sensor_id", "assigned_at", "resolution_reason"]
AUDIT_FIELDS = ["event_id", "entity_type", "entity_id", "action", "actor", "at", "ip", "location",
                "from_status", "to_status", "details"]

# Память одного запуска. Ключ датчика — строка вида site_01/temperature.
sites, sensors, seen, critical = {}, {}, {}, {}
incidents, measurements, alerts, notifications = [], [], [], []
processed = set()
now = datetime.now(timezone.utc)


# Загрузка данных и основные функции исходной заготовки.


def load_sites():
    result = {}
    with open(SITES_CSV, encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            result[row["site_id"]] = row
    return result


def calc_severity(value, norm_min, norm_max):
    if value == "" or value is None:
        return "STALE"
    if isinstance(value, bool):
        raise ValueError("Ожидалось число")
    v, lo, hi = float(value), float(norm_min), float(norm_max)
    if not math.isfinite(v) or not math.isfinite(lo) or not math.isfinite(hi) or lo <= 0 or hi < lo:
        raise ValueError("Неверное число или границы нормы")
    if lo <= v <= hi:
        return "NORMAL"
    if v > hi:
        deviation = (v - hi) / hi * 100
    else:
        deviation = (lo - v) / lo * 100
    if round(deviation, 8) > 10:
        return "CRITICAL"
    return "WARNING"


def check_indicator(row, timer=False, csv_input=False):
    started = time.perf_counter()
    if not isinstance(row, dict):
        return ("ERROR", make_error("VALIDATION_ERROR", "event", "EXPECTED_OBJECT"))
    if not isinstance(row.get("location"), str) or row.get("location") not in sites:
        return ("ERROR", make_error("VALIDATION_ERROR", "location", "UNKNOWN_LOCATION"))
    if row.get("indicator") not in ["temperature", "humidity", "ventilation"]:
        return ("ERROR", make_error("VALIDATION_ERROR", "indicator", "INVALID_INDICATOR"))
    key = row["location"] + "/" + row["indicator"]
    if not timer:
        # Внешний формат из 10_API.yaml. Пустое value допускается только у CSV-эмулятора.
        fields = ["event_id", "time", "location", "indicator", "value", "signature"]
        for field in row:
            if field not in fields:
                return ("ERROR", make_error("VALIDATION_ERROR", field, "UNEXPECTED_FIELD"))
        for field in fields:
            if field not in row:
                return ("ERROR", make_error("VALIDATION_ERROR", field, "REQUIRED_FIELD"))
        if not isinstance(row["event_id"], str) or not re.fullmatch(r"evt_[A-Za-z0-9]{6,32}", row["event_id"]):
            return ("ERROR", make_error("VALIDATION_ERROR", "event_id", "INVALID_EVENT_ID"))
        value = row["value"]
        if not (csv_input and value == ""):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return ("ERROR", make_error("VALIDATION_ERROR", "value", "EXPECTED_NUMBER"))
        if not isinstance(row["signature"], str) or not row["signature"].isascii():
            return ("ERROR", make_error("SENSOR_SIGNATURE_INVALID"))
        try:
            get_time(row)
            if not hmac.compare_digest(row.get("signature", ""), signature(row)):
                return ("ERROR", make_error("SENSOR_SIGNATURE_INVALID"))
            if row["event_id"] in processed:
                return ("DUPLICATE", "DUPLICATE_EVENT")
            limits = sensors.get(key, {}).get("row", {})
            row = row.copy()
            row.setdefault("norm_min", limits.get("norm_min", ""))
            row.setdefault("norm_max", limits.get("norm_max", ""))
            calc_severity(row["value"], row["norm_min"], row["norm_max"])
            at = get_time(row)
            if at < now:
                return ("ERROR", make_error("VALIDATION_ERROR", "time", "OUT_OF_ORDER_TIME"))
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            return ("ERROR", make_error("VALIDATION_ERROR"))
        advance_time(at)
        processed.add(row["event_id"])
        sensors[key] = {"row": row.copy(), "last": now, "stale": row["value"] in ["", None]}
    severity = calc_severity(row["value"], row["norm_min"], row["norm_max"])
    measurement_id = f"msr_{len(measurements) + 1:06d}"
    measurements.append({"measurement_id": measurement_id, "sensor_id": key, "time": now.isoformat(),
        "value": row["value"], "norm_min": row["norm_min"], "norm_max": row["norm_max"], "status": severity})
    if severity == "CRITICAL":
        if key in critical and (now - critical[key]).total_seconds() <= 900:
            exists = False
            for incident in incidents:
                if incident.get("sensor_id") == key and incident["status"] != "CLOSED":
                    exists = True
            if not exists:
                _new_incident({"type": row["indicator"], "location": row["location"],
                               "sensor_id": key, "severity": "CRITICAL"})
        critical[key] = now
    elif not timer:
        critical.pop(key, None)
    if severity == "NORMAL":
        return None
    action = write_alert(row, severity, measurement_id, started)
    if action == "DUPLICATE":
        return ("DUPLICATE", "IGNORED")
    return (severity, action)


def deduplicate(key):
    if key in seen and (now - seen[key]["time"]).total_seconds() < 300:
        return True
    return False


def write_alert(row, severity, measurement_id, started=None):
    key = row["location"] + "/" + row["indicator"]
    if deduplicate(key):
        alert = alerts[seen[key]["index"]]
        if severity != alert["severity"]:
            alert.update({"severity": severity, "value": row["value"], "measurement_id": measurement_id,
                          "updated_at": now.isoformat(), "action": "ALERT_CREATED"})
            if severity in ["CRITICAL", "STALE"]:
                alert["action"] = "ESCALATED"
                notify(alert["alert_id"], row["location"], ["диспетчер", "руководитель"], severity, started)
            write_audit("alert", alert["alert_id"], "severity_changed", location=row["location"], new=severity)
        return "DUPLICATE"
    action = "ALERT_CREATED"
    roles = ["диспетчер"]
    if severity in ["CRITICAL", "STALE"]:
        action = "ESCALATED"
        roles.append("руководитель")
    alert = {"alert_id": f"alrt_{len(alerts) + 1:04d}", "measurement_id": measurement_id,
        "at": now.isoformat(), "updated_at": now.isoformat(), "location": row["location"],
        "indicator": row["indicator"], "value": row["value"], "severity": severity, "action": action}
    seen[key] = {"time": now, "index": len(alerts)}
    alerts.append(alert)
    write_audit("alert", alert["alert_id"], "created", location=row["location"], details=severity)
    notify(alert["alert_id"], row["location"], roles, severity, started)
    return action


def transition_incident(incident, to_status, token, responsible="", resolution_reason=""):
    actor = get_user(token)
    current = incident["status"]
    roles = ["руководитель"]
    if to_status == "ASSIGNED":
        roles.append("диспетчер")
    if to_status == "IN_PROGRESS":
        roles = ["инженер"]
    if not allowed(actor, incident["location"], roles):
        return (False, make_error("FORBIDDEN"))
    if to_status not in ALLOWED_TRANSITIONS.get(current, []):
        return (False, make_error("INVALID_TRANSITION"))
    if to_status == "ASSIGNED":
        if not allowed(responsible, incident["location"], ["инженер"]):
            return (False, make_error("INVALID_RESPONSIBLE"))
        incident["responsible"] = responsible
        incident["assigned_at"] = now.isoformat()
    if to_status == "IN_PROGRESS" and actor != incident["responsible"]:
        return (False, make_error("FORBIDDEN"))
    if to_status == "CLOSED":
        if current == "ASSIGNED" and resolution_reason != "NO_ACTION":
            return (False, make_error("NO_ACTION_REQUIRED"))
        incident["resolution_reason"] = resolution_reason
    incident["status"] = to_status
    action = "incident_" + {"ASSIGNED": "assigned", "IN_PROGRESS": "started", "CLOSED": "closed"}[to_status]
    write_audit("incident", incident["incident_id"], action, actor, incident["location"], current, to_status)
    return (True, None)


# Помощники: время, подписи, права, инциденты, аудит и результаты.


def get_time(row):
    text = row["time"]
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})", text):
        raise ValueError("Неверный формат времени")
    value = datetime.fromisoformat(text.upper().replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("У времени должен быть часовой пояс")
    return value.astimezone(timezone.utc)


def signature(row):
    # Секрет датчика только в окружении. Саму подпись в расчет не включаем.
    key_name = "SC_KEY_" + row["location"].upper() + "_" + row["indicator"].upper()
    key = os.environ.get(key_name, "")
    if len(key) < 32:
        raise ValueError("Не задан " + key_name)
    data = row.copy()
    data.pop("signature", None)
    text = json.dumps(data, sort_keys=True, ensure_ascii=False, allow_nan=False)
    return hmac.new(key.encode(), text.encode("utf-8"), hashlib.sha256).hexdigest()


def get_user(token):
    if not isinstance(token, str) or not token or not token.isascii():
        return ""
    found = ""
    for user_id in USERS:
        expected = os.environ.get("SC_TOKEN_" + user_id.upper(), "")
        if len(expected) >= 24 and expected.isascii() and hmac.compare_digest(token, expected):
            if found:
                return ""
            found = user_id
    return found


def make_error(code, field="", reason=""):
    details = {}
    if field:
        details = {"field": field, "code": reason}
    return {"error_code": code, "message": code, "retryable": False, "details": details}


def allowed(user_id, location, roles):
    if user_id not in USERS or location not in sites:
        return False
    user = USERS[user_id]
    return user["role"] in roles and sites[location]["zone"] in user["zones"]


def create_incident(data, token):
    if not isinstance(data, dict):
        return (None, make_error("VALIDATION_ERROR", "event", "EXPECTED_OBJECT"))
    location = data.get("location", "")
    if not isinstance(location, str) or location not in sites:
        return (None, make_error("VALIDATION_ERROR", "location", "UNKNOWN_LOCATION"))
    actor = get_user(token)
    if not allowed(actor, location, ["диспетчер", "руководитель", "инженер"]):
        return (None, make_error("FORBIDDEN"))
    return _new_incident(data, actor, "mobile")


def _new_incident(data, actor="system", source="auto"):
    # Внутренняя функция: вызов после проверки пользователя или подписи датчика.
    location = data["location"]
    severity = data.get("severity", "WARNING")
    if severity not in SLA or data.get("status", "NEW") != "NEW" or data.get("type") not in ["temperature", "humidity", "ventilation", "equipment", "other"]:
        return (None, make_error("VALIDATION_ERROR"))
    number = 1
    for item in incidents:
        number = max(number, int(item["incident_id"].replace("inc_", "")) + 1)
    incident = {"incident_id": f"inc_{number:03d}", "type": data["type"], "location": location,
        "time": now.isoformat(), "responsible": "", "status": "NEW", "severity": severity,
        "deadline": (now + timedelta(minutes=SLA[severity][1])).isoformat(),
        "source": source, "sensor_id": data.get("sensor_id", ""),
        "assigned_at": "", "resolution_reason": ""}
    incidents.append(incident)
    write_audit("incident", incident["incident_id"], "incident_created", actor, location, new="NEW")
    return (incident, None)


def write_audit(entity_type, entity_id, action, actor="system", location="", old="", new="", details=""):
    os.makedirs(OUT_DIR, exist_ok=True)
    path = os.path.join(OUT_DIR, "audit.csv")
    new_file = not os.path.exists(path)
    event = {"event_id": "evt_" + uuid.uuid4().hex, "entity_type": entity_type,
        "entity_id": entity_id, "action": action, "actor": actor, "at": now.isoformat(),
        "ip": "local", "location": location, "from_status": old, "to_status": new, "details": details}
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        if new_file:
            writer.writeheader()
        writer.writerow(event)


def notify(entity_id, location, roles, message, started=None):
    delay_ms = 0.0
    if started is not None:
        delay_ms = (time.perf_counter() - started) * 1000
    for user_id in USERS:
        if allowed(user_id, location, roles):
            notifications.append({"user_id": user_id, "entity_id": entity_id, "location": location,
                "message": message, "at": now.isoformat(), "delivery_ms": round(delay_ms, 3)})
    entity_type = "alert"
    if entity_id.startswith("inc_"):
        entity_type = "incident"
    write_audit(entity_type, entity_id, "notified", location=location, details=message)


def view_data(token, kind):
    actor = get_user(token)
    if not actor:
        return (None, make_error("UNAUTHORIZED"))
    role = USERS[actor]["role"]
    if kind == "sites":
        rows = list(sites.values())
    elif kind == "incidents" and role != "администратор":
        rows = incidents
    elif kind == "alerts" and role in ["диспетчер", "руководитель"]:
        rows = alerts
    elif kind == "inbox" and role in ["диспетчер", "руководитель"]:
        rows = notifications
    elif kind == "audit" and role in ["диспетчер", "руководитель"]:
        path = os.path.join(OUT_DIR, "audit.csv")
        rows = []
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
    else:
        return (None, make_error("FORBIDDEN"))
    result = []
    for row in rows:
        location = row.get("location", row.get("site_id", ""))
        if not allowed(actor, location, [role]):
            continue
        if kind == "incidents" and role == "инженер" and row.get("responsible") != actor:
            continue
        if kind == "inbox" and row["user_id"] != actor:
            continue
        result.append(row.copy())
    if kind == "alerts":
        ordered = []
        for severity in ["CRITICAL", "STALE", "WARNING"]:
            for row in result:
                if row["severity"] == severity:
                    ordered.append(row)
        result = ordered
    return (result, None)


def edit_site(token, site_id, name, zone=""):
    actor = get_user(token)
    if not actor or USERS[actor]["role"] != "администратор":
        return (False, make_error("FORBIDDEN"))
    if not isinstance(site_id, str) or len(site_id) != 7 or not site_id.startswith("site_") or not site_id[5:].isdigit():
        return (False, make_error("INVALID_SITE_ID"))
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100:
        return (False, make_error("INVALID_NAME"))
    old_zone = sites.get(site_id, {}).get("zone", "")
    zone = zone or old_zone
    if zone not in USERS[actor]["zones"] or (old_zone and old_zone not in USERS[actor]["zones"]):
        return (False, make_error("FORBIDDEN"))
    sites[site_id] = {"site_id": site_id, "name": name.strip(), "zone": zone}
    write_audit("site", site_id, "updated", actor, site_id)
    return (True, None)


def advance_time(target):
    global now
    if target < now:
        raise ValueError("Нельзя перевести время назад")

    # Сначала собираем сроки. Номер нужен для событий с одинаковым временем.
    events = []
    for sensor in sensors.values():
        if not sensor["stale"]:
            at = sensor["last"] + timedelta(seconds=301)
            events.append((at, len(events), "stale", sensor))
    for incident in incidents:
        if incident["status"] == "CLOSED":
            continue
        if not incident.get("closure_sent"):
            at = get_time({"time": incident["deadline"]}) + timedelta(seconds=1)
            events.append((at, len(events), "closure", incident))
        if incident.get("severity") in SLA and incident["status"] == "NEW" and not incident.get("reaction_sent"):
            minutes = SLA[incident["severity"]][0]
            at = get_time(incident) + timedelta(minutes=minutes, seconds=1)
            events.append((at, len(events), "reaction", incident))

    # Затем обрабатываем наступившие события по времени, без ожидания на часах.
    for at, number, kind, item in sorted(events):
        if at > target:
            break
        now = max(now, at)
        if kind == "stale":
            item["stale"] = True
            row = item["row"].copy()
            row.update({"value": "", "time": now.isoformat()})
            check_indicator(row, timer=True)
        else:
            item[kind + "_sent"] = True
            roles = ["руководитель"]
            if item.get("severity") == "WARNING":
                roles = ["диспетчер"]
            notify(item["incident_id"], item["location"], roles, "SLA_OVERDUE:" + kind)
    now = target


def save_results():
    os.makedirs(OUT_DIR, exist_ok=True)
    for name, fields, rows in [("alerts_out.csv", OUT_FIELDS, alerts), ("incidents_out.csv", INCIDENT_FIELDS, incidents)]:
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
    for name, rows in [("measurements.json", measurements), ("inbox.json", notifications), ("sites.json", list(sites.values()))]:
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)


def main():
    global now
    # Как в заготовке: пути -> CSV -> проверка показаний -> результаты.
    incidents_path = INCIDENTS_CSV
    indicators_path = INDICATORS_CSV
    if "--incidents" in sys.argv:
        incidents_path = sys.argv[sys.argv.index("--incidents") + 1]
    if "--indicators" in sys.argv:
        indicators_path = sys.argv[sys.argv.index("--indicators") + 1]
    sites.update(load_sites())
    with open(incidents_path, encoding="utf-8-sig") as f:
        incidents.extend(csv.DictReader(f))
    with open(indicators_path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    rows.sort(key=get_time)
    if rows:
        now = get_time(rows[0])

    # CSV изображает датчики. Секреты создаются в окружении, не в коде и не в файлах.
    for user_id in USERS:
        os.environ.setdefault("SC_TOKEN_" + user_id.upper(), secrets.token_hex(32))
    for row in rows:
        if row["location"] not in sites:
            continue
        key = row["location"] + "/" + row["indicator"]
        if key not in sensors:
            sensors[key] = {"row": row.copy(), "last": now, "stale": False}
        key_name = "SC_KEY_" + row["location"].upper() + "_" + row["indicator"].upper()
        os.environ.setdefault(key_name, secrets.token_hex(32))

    for number, row in enumerate(rows):
        event = row
        if row["location"] in sites:
            try:
                value = ""
                if row["value"] != "":
                    value = float(row["value"])
            except ValueError:
                print("422", make_error("VALIDATION_ERROR", "value", "EXPECTED_NUMBER"))
                continue
            # Нормы остаются в каталоге. Внешнее событие содержит только поля схемы.
            event = {"event_id": f"evt_{number:06d}", "time": row["time"],
                     "location": row["location"], "indicator": row["indicator"], "value": value}
            event["signature"] = signature(event)
        result = check_indicator(event, csv_input=True)
        if result is not None and result[0] in ["ERROR", "DUPLICATE"]:
            print(result)
            if result[0] == "ERROR":
                write_audit("measurement", str(event.get("event_id", "")), "rejected",
                            location=row.get("location", ""), details=json.dumps(result[1], ensure_ascii=False))

    advance_time(now + timedelta(minutes=6))
    save_results()
    print("Показаний:", len(rows), "Алертов:", len(alerts), "Инцидентов:", len(incidents))
    print("Результаты:", OUT_DIR)
    print("Уведомления локальные. Время модельное. Исходные CSV не изменяются.")


if __name__ == "__main__":
    main()
