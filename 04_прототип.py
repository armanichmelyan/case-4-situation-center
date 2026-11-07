#!/usr/bin/env python3
"""
CLI-прототип ситуационного центра — кейс 4.

Использование:
    python 04_прототип.py
    python 04_прототип.py --incidents incidents.csv --indicators indicators.csv
    python 04_прототип.py --sla         # дополнительно вывести просроченные по SLA
    python 04_прототип.py --demo        # примеры для скриншотов T4-2 и T4-5

Что делает:
    читает indicators.csv, применяет правила A-1…A-5, выводит оповещения
    в консоль и в alerts_out.csv, создаёт автоинциденты (A-3, source=auto),
    проверяет переходы статусов инцидента, ведёт аудит (audit_out.csv)
    и проверяет SLA реакции и закрытия.

Внешние события требуют HMAC; чтение локального CSV — доверенный эмулятор.
Личность пользователя не проверяется: оператор задает роль, идентификатор и зоны.
check_indicator обрабатывает доверенные CSV; внешний вход — check_external_indicator.
"""
import csv
import os
import sys
import math
import time
import re
import json
import hmac
import hashlib
from uuid import uuid4
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def data_path(name):
    """Ищем файл в 01_данные/, а если папки нет — рядом со скриптом."""
    p = os.path.join(BASE_DIR, "01_данные", name)
    return p if os.path.exists(p) else os.path.join(BASE_DIR, name)


SITES_CSV = data_path("sites.csv")
INCIDENTS_CSV = data_path("incidents.csv")
INDICATORS_CSV = data_path("indicators.csv")
OUT_CSV = os.path.join(BASE_DIR, "alerts_out.csv")
AUDIT_CSV = os.path.join(BASE_DIR, "audit_out.csv")
AUTO_INCIDENTS_CSV = os.path.join(BASE_DIR, "auto_incidents_out.csv")
INCIDENTS_STATE_CSV = os.path.join(BASE_DIR, "incidents_out.csv")
SITES_STATE_CSV = os.path.join(BASE_DIR, "sites_out.csv")
INBOX_CSV = os.path.join(BASE_DIR, "notifications_out.csv")
INBOX_FIELDS = ["at", "entity_type", "entity_id", "location", "zone", "to_role", "message", "delivery_ms"]
SLA = {"CRITICAL": (15, 60), "WARNING": (60, 240), "STALE": (30, 60)}
DEFAULT_ZONES = {
    "Диспетчер": ["zone_A"], "Руководитель": ["zone_A", "zone_B", "zone_C"],
    "Инженер": ["zone_A"], "Администратор": ["zone_A", "zone_B", "zone_C"],
    "system": ["zone_A", "zone_B", "zone_C"],
}
# Учебный профиль зон согласован с назначениями исходного CSV и примером T4-1.
# Это настройка команды, а не проверка личности сотрудника.
ENGINEERS = {"e_101": ["zone_A", "zone_C"], "e_102": ["zone_A"], "e_103": ["zone_A"],
             "e_104": ["zone_B"], "e_105": ["zone_B"]}
PROCESSED_EVENTS = set()

# Окна времени из правил оповещений (02_правила.md)
DEDUP_WINDOW = timedelta(minutes=5)      # A-5
AUTO_WINDOW = timedelta(minutes=15)      # A-3
STALE_TIMEOUT = timedelta(minutes=5)     # A-4
SLA_CLOSE_CRITICAL = timedelta(hours=1)  # SLA закрытия для CRITICAL (02_правила.md, п. 4)

OUT_FIELDS = ["measurement_id", "alert_id", "at", "location", "indicator", "value", "severity", "action"]
AUDIT_FIELDS = ["event_id", "entity_type", "entity_id", "action",
                "from_status", "to_status", "actor", "at", "ip"]
INCIDENT_FIELDS = ["incident_id", "type", "location", "time", "responsible",
                   "status", "deadline", "source", "severity", "assigned_at", "resolution_reason", "response_notified", "closure_notified"]

# Кто может создавать инциденты (администратор и неизвестные роли — нет).
# "system" — сама программа при автоинциденте (A-3).
ROLES_CAN_CREATE = ("Диспетчер", "Руководитель", "Инженер", "system")

# Жизненный цикл инцидента: NEW -> ASSIGNED -> IN_PROGRESS -> CLOSED;
# ASSIGNED -> CLOSED разрешён только для ложного вызова (проверка ниже)
ALLOWED_TRANSITIONS = {
    "NEW": ["ASSIGNED"],
    "ASSIGNED": ["IN_PROGRESS", "CLOSED"],
    "IN_PROGRESS": ["CLOSED"],
    "CLOSED": [],
}

# Внутренний короткий код ошибки -> (error_code по схеме Error из 10_API.yaml,
# сообщение, поле для details). Все функции возвращают ошибку в одном формате.
ERROR_MAP = {
    "BAD_DATA": ("VALIDATION_ERROR", "Неверный формат события или границы нормы", "event"),
    "SENSOR_SIGNATURE_INVALID": ("SENSOR_SIGNATURE_INVALID", "Подпись отсутствует или неверна", "signature"),
    "FORBIDDEN": ("FORBIDDEN", "Нет доступа к действию или зоне", "actor"),
    "UNKNOWN_LOCATION": ("VALIDATION_ERROR", "Участок не найден в sites.csv", "location"),
    "INVALID_ROLE": ("VALIDATION_ERROR", "Роль не имеет права на это действие", "actor"),
    "NOT_RESPONSIBLE": ("VALIDATION_ERROR", "Инцидент назначен другому инженеру", "actor"),
    "RESPONSIBLE_REQUIRED": ("VALIDATION_ERROR", "Не назначен ответственный", "responsible"),
    "INVALID_RESOLUTION_REASON": ("VALIDATION_ERROR",
                                  "Закрытие из ASSIGNED только с resolution_reason=NO_ACTION",
                                  "resolution_reason"),
    "INVALID_TRANSITION": ("INVALID_TRANSITION", "Переход запрещён жизненным циклом", None),
    "DUPLICATE": ("DUPLICATE_EVENT", "Повтор события в окне 5 минут", None),
}


def api_error(code):
    """Ошибка в формате схемы Error (10_API.yaml): error_code, message, retryable, details."""
    error_code, message, field = ERROR_MAP[code]
    err = {"error_code": error_code, "message": message, "retryable": False}
    if field:
        err["details"] = {"field": field, "code": code}
    return err


def load_sites():
    """Исходный CSV не меняется; изменения справочника хранятся отдельно."""
    result = {}
    for row in read_rows(SITES_CSV) + read_rows(SITES_STATE_CSV):
        result[row["site_id"]] = row
    return result


def parse_time(s):
    if not isinstance(s, str):
        raise ValueError("Время должно быть строкой")
    result = datetime.fromisoformat(s.upper().replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("У времени должен быть часовой пояс")
    return result.astimezone(timezone.utc)


def fmt_time(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def calc_deviation(value, norm_min, norm_max):
    """Отклонение от нормы в процентах (0, если значение в норме)."""
    v, lo, hi = float(value), float(norm_min), float(norm_max)
    if lo <= v <= hi:
        return 0.0
    if v > hi:
        return (v - hi) / hi * 100
    return (lo - v) / lo * 100


def calc_severity(value, norm_min, norm_max):
    """Формула severity из 02_правила.md: NORMAL / WARNING / CRITICAL / STALE."""
    # нет данных -> STALE (без показания нельзя судить о норме)
    if value == "" or value is None:
        return "STALE"
    if isinstance(value, bool):
        raise ValueError("Нужно число")
    v = float(value)
    lo, hi = float(norm_min), float(norm_max)
    # защита от некорректных чисел и границ нормы
    if not math.isfinite(v) or not math.isfinite(lo) or not math.isfinite(hi) or lo <= 0 or hi < lo:
        raise ValueError("Неверное число или границы нормы")
    # граница нормы включительная: value == norm_max это NORMAL
    if lo <= v <= hi:
        return "NORMAL"
    # отклонение > 10% -> CRITICAL, иначе WARNING (порог 5% на результат не влияет);
    # round убирает ошибки float на границе ровно 10%
    if round(calc_deviation(v, lo, hi), 8) > 10:
        return "CRITICAL"
    return "WARNING"


def new_state(now, sev, streak=0, last_rx=None, stale_sent=False):
    """Память по датчику (seen).

    time       - время последнего обработанного показания (для A-3)
    alert_time - время последнего созданного алерта (для A-5), None если алерта нет
    alert_sev  - текущий уровень последнего алерта
    last_rx    - время последнего ПОЛУЧЕННОГО показания, включая дубли (для A-4)
    stale_sent - STALE по таймауту уже выдан, повторно не выдаём
    """
    return {"time": now, "sev": sev, "streak": streak,
            "last_rx": last_rx, "stale_sent": stale_sent,
            "alert_time": now if sev != "NORMAL" else None,
            "alert_sev": sev if sev != "NORMAL" else None}


def check_indicator(row, sites, seen, *, trusted_csv=True):
    """Правила A-1…A-5.

    Возвращает список результатов [(severity, action), ...]:
      []                                  - NORMAL, алерт не нужен
      [("STALE", "ESCALATED")]            - A-4
      [("STALE", ...), ("CRITICAL", ...)] - молчал > 5 мин, и пришло новое показание
    Ошибка локации: [("ERROR", "UNKNOWN_LOCATION")].
    Действие "AUTO_INCIDENT" — внутренний сигнал для main(), в файл не попадает.
    """
    if not isinstance(row, dict):
        return [("ERROR", "BAD_DATA")]
    loc = row.get("location")
    if not isinstance(loc, str) or loc not in sites:
        return [("ERROR", "UNKNOWN_LOCATION")]
    if row.get("indicator") not in ("temperature", "humidity", "ventilation"):
        return [("ERROR", "BAD_DATA")]

    if not trusted_csv:
        fields = {"event_id", "time", "location", "indicator", "value", "signature"}
        if set(row) != fields:
            return [("ERROR", "BAD_DATA")]
        if not isinstance(row["event_id"], str) or not re.fullmatch(r"evt_[A-Za-z0-9]{6,32}", row["event_id"]):
            return [("ERROR", "BAD_DATA")]
        if isinstance(row["value"], bool) or not isinstance(row["value"], (int, float)):
            return [("ERROR", "BAD_DATA")]
        if not verify_signature(row):
            return [("ERROR", "SENSOR_SIGNATURE_INVALID")]
        limits = indicator_norms(loc, row["indicator"])
        if limits is None:
            return [("ERROR", "BAD_DATA")]
        row = {**row, **limits}

    try:
        now = parse_time(row["time"])
        if now.tzinfo is None:
            return [("ERROR", "BAD_DATA")]
        sev = calc_severity(row["value"], row["norm_min"], row["norm_max"])
    except (ValueError, TypeError, KeyError, OverflowError):
        return [("ERROR", "BAD_DATA")]
    if not trusted_csv:
        event_key = (loc, row["indicator"], row["event_id"])
        if event_key in PROCESSED_EVENTS:
            return [("DUPLICATE", "IGNORED")]
    key = (loc, row["indicator"])
    pred = seen.get(key)
    if pred and now < pred["time"]:
        return [("ERROR", "BAD_DATA")]
    if not trusted_csv:
        PROCESSED_EVENTS.add(event_key)
    streak = (pred["streak"] + 1 if pred and pred["sev"] == "CRITICAL"
              and timedelta(0) <= now - pred["time"] <= AUTO_WINDOW else 1) if sev == "CRITICAL" else 0
    anchor = pred.get("alert_time") if pred else None
    duplicate = (anchor is not None and sev != "NORMAL"
                 and timedelta(0) <= now - anchor < DEDUP_WINDOW)
    if duplicate:
        previous = pred.get("alert_sev")
        seen[key] = new_state(now, sev, streak,
                              last_rx=now if sev != "STALE" else pred["last_rx"],
                              stale_sent=sev == "STALE")
        seen[key]["alert_time"] = anchor
        results = [("DUPLICATE", "IGNORED")]
        if sev != previous:
            results.append((sev, "UPDATE_ALERT"))
        if streak >= 2:
            results.append(("CRITICAL", "AUTO_ONLY"))
        return results

    # A-4: пустое значение -> STALE + эскалация
    if sev == "STALE":
        seen[key] = new_state(now, "STALE", 0,
                              last_rx=pred["last_rx"] if pred else None, stale_sent=True)
        return [("STALE", "ESCALATED")]

    results = []

    # A-4: с прошлого показания прошло больше 5 минут -> STALE + эскалация
    # (в main() это обычно уже выдано потоковой проверкой, тогда stale_sent=True)
    if (pred and pred["last_rx"] and not pred["stale_sent"]
            and now - pred["last_rx"] > STALE_TIMEOUT):
        results.append(("STALE", "ESCALATED"))

    # дальше оцениваем само пришедшее показание (STALE выше не мешает ему:
    # иначе реальный WARNING/CRITICAL терялся бы)
    if sev == "NORMAL":
        seen[key] = new_state(now, "NORMAL", 0, last_rx=now)
        if anchor is not None:
            seen[key]["alert_time"] = anchor
            seen[key]["alert_sev"] = pred.get("alert_sev")
        return results

    if sev == "WARNING":                           # A-1
        seen[key] = new_state(now, "WARNING", 0, last_rx=now)
        results.append(("WARNING", "ALERT_CREATED"))
        return results

    # CRITICAL (A-2) + серия подряд (A-3): считаем подряд идущие CRITICAL
    # в окне 15 минут; NORMAL/WARNING между ними обнуляют серию
    if pred and pred["sev"] == "CRITICAL" and timedelta(0) <= now - pred["time"] <= AUTO_WINDOW:
        streak = pred["streak"] + 1
    else:
        streak = 1
    seen[key] = new_state(now, "CRITICAL", streak, last_rx=now)

    if streak >= 2:
        results.append(("CRITICAL", "AUTO_INCIDENT"))   # создать инцидент source=auto
    else:
        results.append(("CRITICAL", "ESCALATED"))
    return results


def find_silent_sensors(seen, now):
    """A-4: датчики, от которых нет показаний больше 5 минут (и STALE ещё не выдан).

    Нужна отдельно от check_indicator: замолчавший датчик не присылает строк,
    поэтому check_indicator для него просто не вызывается.
    Возвращает [(время_последнего_показания, ключ), ...] по возрастанию времени.
    """
    return sorted((v["last_rx"], key) for key, v in seen.items()
                  if v["last_rx"] and not v["stale_sent"]
                  and now - v["last_rx"] > STALE_TIMEOUT)


def find_sla_overdue(incidents, now):
    """Срок закрытия — по deadline; срок реакции — только при известном severity.
    У старых импортированных записей неизвестный уровень не выдумывается.
    """
    overdue = []
    for i in incidents:
        reasons = []
        if i.get("status") == "CLOSED":
            continue
        if i.get("deadline") and parse_time(i["deadline"]) < now:
            reasons.append("closure")
        minutes = {"CRITICAL": 15, "WARNING": 60, "STALE": 30}.get(i.get("severity"))
        if minutes and i.get("time"):
            due = parse_time(i["time"]) + timedelta(minutes=minutes)
            assigned = i.get("assigned_at")
            if (assigned and parse_time(assigned) > due) or (not assigned and i.get("status") == "NEW" and now > due):
                reasons.append("response")
        if reasons:
            overdue.append({**i, "sla_breaches": ",".join(reasons)})
    return overdue


def write_alert(alert):
    if os.path.exists(OUT_CSV):
        with open(OUT_CSV, encoding="utf-8-sig") as existing:
            if next(csv.reader(existing), []) != OUT_FIELDS:
                raise ValueError("alerts_out.csv от другой версии: сохраните его отдельно и начните новый отчет")
    new_file = not os.path.exists(OUT_CSV)
    with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        if new_file:
            w.writeheader()
        w.writerow(alert)


def audit_log(audit, action, actor, entity_id, entity_type="incident",
              from_status=None, to_status=None, ip=None):
    """Запись аудита (поля из 08_ER.md и 11_ИБ.md). action: created / assigned /
    status_changed / closed. entity_type: incident / alert."""
    if audit is None:
        audit = []
    audit.append({
        "event_id": "evt_" + uuid4().hex,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "action": action,
        "from_status": from_status,
        "to_status": to_status,
        "actor": actor,
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ip": ip or "local",
    })
    write_rows(AUDIT_CSV, AUDIT_FIELDS, [audit[-1]])


def write_rows(path, fields, rows):
    """Сохранить записи в CSV (только дозапись, существующие строки не меняем)."""
    new_file = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        if new_file:
            w.writeheader()
        w.writerows(rows)


def create_incident(data, sites, actor_role, audit=None, *, actor_id=None, actor_zones=None):
    """Создать NEW; роль доверенно задает оператор, без аутентификации."""
    if actor_role not in ROLES_CAN_CREATE:
        return None, api_error("INVALID_ROLE")
    if not isinstance(data, dict):
        return None, api_error("BAD_DATA")
    location = data.get("location")
    if not isinstance(location, str) or location not in sites:
        return None, api_error("UNKNOWN_LOCATION")
    if not allowed_zone(actor_role, sites, location, actor_zones, actor_id):
        return None, api_error("FORBIDDEN")
    if data.get("type") not in ("temperature", "humidity", "ventilation", "equipment", "other"):
        return None, api_error("BAD_DATA")
    severity = data.get("severity", "WARNING")
    if severity not in SLA or data.get("status", "NEW") != "NEW":
        return None, api_error("BAD_DATA")
    try:
        at = parse_time(data["time"]) if data.get("time") else datetime.now(timezone.utc)
        deadline = parse_time(data["deadline"]) if data.get("deadline") else at + timedelta(minutes=SLA[severity][1])
    except (ValueError, TypeError):
        return None, api_error("BAD_DATA")
    used = existing_ids()
    ident = data.get("incident_id") or next_incident_id(used)
    if not isinstance(ident, str) or not re.fullmatch(r"inc_[0-9]{3}", ident):
        return None, api_error("BAD_DATA")
    if ident in used:
        return None, api_error("DUPLICATE")
    USED_IDS.add(ident)
    inc = {**data, "incident_id": ident, "status": "NEW", "location": location,
           "time": fmt_time(at), "deadline": fmt_time(deadline), "severity": severity,
           "responsible": data.get("responsible") or None,
           "source": "auto" if actor_role == "system" else "mobile"}
    RUN_INCIDENTS.append(inc)
    save_incidents()
    audit_log(audit, "created", actor_id or actor_role, ident, to_status="NEW")
    return inc, None


def transition_incident(incident, to_status, actor_role, actor_id=None, audit=None,
                        *, sites=None, actor_zones=None, at=None):
    """Разрешенный переход и сохранение состояния; at нужен для учебных сценариев."""
    sites = load_sites() if sites is None else sites
    if not allowed_zone(actor_role, sites, incident.get("location"), actor_zones, actor_id):
        return False, api_error("FORBIDDEN")
    current = incident["status"]
    if to_status not in ALLOWED_TRANSITIONS.get(current, []):
        return False, api_error("INVALID_TRANSITION")
    if to_status == "ASSIGNED":
        if actor_role not in ("Диспетчер", "Руководитель"):
            return False, api_error("INVALID_ROLE")
        engineer = incident.get("responsible")
        if (engineer not in ENGINEERS
                or sites[incident["location"]]["zone"] not in ENGINEERS[engineer]):
            return False, api_error("RESPONSIBLE_REQUIRED")
    elif to_status == "IN_PROGRESS":
        if actor_role != "Инженер":
            return False, api_error("INVALID_ROLE")
        if actor_id != incident.get("responsible"):
            return False, api_error("NOT_RESPONSIBLE")
    elif to_status == "CLOSED":
        if actor_role != "Руководитель":
            return False, api_error("INVALID_ROLE")
        if current == "ASSIGNED" and incident.get("resolution_reason") != "NO_ACTION":
            return False, api_error("INVALID_RESOLUTION_REASON")
    try:
        action_time = parse_time(at) if at else datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False, api_error("BAD_DATA")
    incident["status"] = to_status
    if to_status == "ASSIGNED":
        incident["assigned_at"] = fmt_time(action_time)
    RUN_INCIDENTS[:] = [r for r in RUN_INCIDENTS if r["incident_id"] != incident["incident_id"]]
    RUN_INCIDENTS.append(incident)
    save_incidents()
    action = {"ASSIGNED": "assigned", "CLOSED": "closed"}.get(to_status, "status_changed")
    audit_log(audit, action, actor_id or actor_role, incident["incident_id"],
              from_status=current, to_status=to_status)
    return True, None


def emit_alert(ctx, sites, at, loc, ind, value, severity, action, note=""):
    """Создать алерт: строка в alerts_out.csv, запись в аудит, вывод в консоль.
    При AUTO_INCIDENT создаёт автоинцидент (source=auto), но только если по этому
    датчику ещё нет открытого автоинцидента."""
    auto_only = action == "AUTO_ONLY"
    update = action in ("UPDATE_ALERT", "AUTO_ONLY")
    previous = ctx.setdefault("last_alert", {}).get((loc, ind))
    if update and previous is None:
        update = False
        auto_only = False
    if not update:
        ctx["alerts"] += 1
    alert_id = previous["alert_id"] if update else next_alert_id()
    measurement_id = ctx.get("measurement_id")
    if not measurement_id:
        measurement_id = "msr_" + uuid4().hex
        write_rows(MEASUREMENTS_CSV, MEASUREMENT_FIELDS,
                   [{"measurement_id": measurement_id, "sensor_id": loc + "/" + ind,
                     "time": at, "location": loc, "indicator": ind, "value": value,
                     **(indicator_norms(loc, ind) or {}),
                     "status": severity}])
    new_inc = None

    if action in ("AUTO_INCIDENT", "AUTO_ONLY"):              # A-3
        key = (loc, ind)
        existing = ctx["open_auto"].get(key)
        if not existing or existing["status"] == "CLOSED":
            time_dt = parse_time(at)
            new_inc, _ = create_incident(
                {"incident_id": next_incident_id(existing_ids()), "severity": "CRITICAL",
                 "type": ind, "location": loc, "time": at, "responsible": "",
                 "deadline": fmt_time(time_dt + SLA_CLOSE_CRITICAL),   # SLA CRITICAL: 1 ч
                 "source": "auto"},
                sites, "system", ctx["audit"])
            ctx["open_auto"][key] = new_inc
            ctx["auto"].append(new_inc)
        # в схеме Alert.action значения AUTO_INCIDENT нет: алерт — эскалация,
        # а инцидент хранится отдельной записью
        action = "ESCALATED"

    if update:
        if previous and not auto_only:
            previous.update(measurement_id=measurement_id, value=value, severity=severity,
                            action="ESCALATED" if severity in ("CRITICAL", "STALE") else "ALERT_CREATED")
            replace_alert(previous)
            roles = ["Диспетчер", "Руководитель"] if severity in ("CRITICAL", "STALE") else ["Диспетчер"]
            notify("alert", alert_id, loc, severity, roles, sites, ctx.get("started"))
            audit_log(ctx["audit"], "updated", "system", alert_id, entity_type="alert")
        if new_inc:
            print(f"    Автоинцидент {new_inc['incident_id']} (source=auto)")
        return
    alert = {"measurement_id": measurement_id, "alert_id": alert_id, "at": at,
             "location": loc, "indicator": ind, "value": value,
             "severity": severity, "action": action}
    ctx["last_alert"][(loc, ind)] = alert
    write_alert(alert)
    roles = ["Диспетчер", "Руководитель"] if severity in ("CRITICAL", "STALE") else ["Диспетчер"]
    notify("alert", alert_id, loc, severity, roles, sites, ctx.get("started"))
    audit_log(ctx["audit"], "created", "system", alert_id, entity_type="alert")
    print(f"[{severity}] {at} {loc} {ind} value={value or '—'} -> {action}"
          + (f"  ({note})" if note else ""))
    if new_inc:
        print(f"    🚨 автоинцидент {new_inc['incident_id']} "
              f"(source={new_inc['source']}, status={new_inc['status']})")


def flush_silent(ctx, sites, seen, now):
    """A-4 по ходу потока: выдать STALE всем, кто молчит > 5 минут на момент `now`.
    Время алерта — момент наступления таймаута (последнее показание + 5 минут)."""
    for last, key in find_silent_sensors(seen, now):
        measurement_id = ctx.pop("measurement_id", None)
        emit_alert(ctx, sites, fmt_time(last + STALE_TIMEOUT), key[0], key[1], "",
                   "STALE", "ESCALATED", note=f"нет данных с {last:%Y-%m-%d %H:%M}")
        if measurement_id:
            ctx["measurement_id"] = measurement_id
        seen[key]["stale_sent"] = True
        seen[key]["alert_time"] = last + STALE_TIMEOUT
        seen[key]["alert_sev"] = "STALE"
        ctx["stale_timeout"] += 1


def demo(sites):
    """Примеры для скриншотов: T4-2 (порог) и T4-5 (STALE)."""
    print("=== T4-2: датчик превысил порог ===")
    row = {"time": "2025-11-01T10:00:00Z", "location": "site_02", "indicator": "temperature",
           "value": "28.3", "norm_min": "20.0", "norm_max": "26.0"}
    dev = calc_deviation(row["value"], row["norm_min"], row["norm_max"])
    print(f"value={row['value']}, norm_max={row['norm_max']}: "
          f"deviation = ({row['value']} - {row['norm_max']}) / {row['norm_max']} × 100 = {dev:.1f}%")
    print("результат:", check_indicator(row, sites, {}, trusted_csv=True))

    print("\n=== T4-5: датчик offline / STALE ===")
    row = {"time": "2025-11-01T10:00:00Z", "location": "site_04", "indicator": "temperature",
           "value": "", "norm_min": "20.0", "norm_max": "26.0"}
    print("value=\"\"")
    print("результат:", check_indicator(row, sites, {}, trusted_csv=True))


# Память текущего прогона, без пользовательских паролей и токенов.
USED_IDS = set()
RUN_INCIDENTS = []
MEASUREMENTS_CSV = os.path.join(BASE_DIR, "measurements_out.csv")
MEASUREMENT_FIELDS = ["measurement_id", "sensor_id", "time", "location", "indicator",
                      "value", "norm_min", "norm_max", "status"]


def read_rows(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def indicator_norms(location, indicator):
    """Нормы хранятся в каталоге CSV, а не во внешнем TelemetryEvent."""
    for row in read_rows(INDICATORS_CSV):
        if row["location"] == location and row["indicator"] == indicator:
            return {"norm_min": row["norm_min"], "norm_max": row["norm_max"]}
    return None


def load_incidents():
    """Последняя сохраненная версия и изменения в памяти имеют приоритет."""
    records = {}
    for row in (read_rows(INCIDENTS_CSV) + read_rows(AUTO_INCIDENTS_CSV)
                + read_rows(INCIDENTS_STATE_CSV) + RUN_INCIDENTS):
        records[row["incident_id"]] = row
    return list(records.values())


def save_incidents():
    """Сохраняем текущее состояние отдельно от неизменяемого исходного CSV."""
    rows = load_incidents()
    RUN_INCIDENTS[:] = rows
    for path, only_auto in ((INCIDENTS_STATE_CSV, False), (AUTO_INCIDENTS_CSV, True)):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=INCIDENT_FIELDS, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                if not only_auto or row.get("source") == "auto":
                    writer.writerow(row)


def existing_ids():
    return USED_IDS | {i["incident_id"] for i in load_incidents()}


def next_alert_id():
    number = 1
    for row in read_rows(OUT_CSV):
        ident = row["alert_id"]
        if re.fullmatch(r"alrt_[0-9]{4}", ident):
            number = max(number, int(ident[5:]) + 1)
    if number > 9999:
        raise ValueError("Исчерпан диапазон alrt_0001...alrt_9999")
    return f"alrt_{number:04d}"


def next_incident_id(used):
    number = 1
    while f"inc_{number:03d}" in used:
        number += 1
    if number > 999:
        raise ValueError("Исчерпан учебный диапазон inc_001...inc_999")
    return f"inc_{number:03d}"




def allowed_zone(actor_role, sites, location, actor_zones=None, actor_id=None):
    """Оператор доверенно задает профиль; это проверка прав, не личности."""
    zones = actor_zones
    if zones is None:
        zones = ENGINEERS.get(actor_id, DEFAULT_ZONES.get(actor_role, [])) if actor_role == "Инженер" else DEFAULT_ZONES.get(actor_role, [])
    return (actor_role in DEFAULT_ZONES and isinstance(location, str)
            and location in sites and sites[location]["zone"] in zones)


def signature(row):
    data = {k: v for k, v in row.items() if k != "signature"}
    payload = json.dumps(data, sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
    key = os.environ["SC_KEY_" + row["location"].upper() + "_" + row["indicator"].upper()]
    return hmac.new(key.encode(), payload, hashlib.sha256).hexdigest()


def verify_signature(row):
    try:
        return isinstance(row.get("signature"), str) and hmac.compare_digest(row["signature"], signature(row))
    except (KeyError, ValueError, TypeError):
        return False


def replace_alert(alert):
    rows = read_rows(OUT_CSV)
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUT_FIELDS)
        writer.writeheader()
        writer.writerows(alert if r["alert_id"] == alert["alert_id"] else r for r in rows)


def view_data(actor_role, kind, sites=None, *, actor_id=None, actor_zones=None):
    sites = load_sites() if sites is None else sites
    if actor_role not in DEFAULT_ZONES or actor_role == "system":
        return None, api_error("FORBIDDEN")
    if kind == "sites":
        return [r for r in sites.values() if allowed_zone(actor_role, sites, r["site_id"], actor_zones, actor_id)], None
    if (kind not in ("incidents", "alerts", "audit", "inbox") or actor_role == "Администратор"
            or (actor_role == "Инженер" and kind != "incidents")):
        return None, api_error("FORBIDDEN")
    incidents = load_incidents()
    alerts = read_rows(OUT_CSV)
    rows = {"incidents": incidents, "alerts": alerts,
            "audit": read_rows(AUDIT_CSV), "inbox": read_rows(INBOX_CSV)}[kind]
    objects = {r["incident_id"]: r for r in incidents}
    objects.update({r["alert_id"]: r for r in alerts})
    objects.update({key: {**row, "location": key} for key, row in sites.items()})
    visible = []
    for row in rows:
        obj = objects.get(row["entity_id"], {}) if kind == "audit" else row
        if not allowed_zone(actor_role, sites, obj.get("location"), actor_zones, actor_id):
            continue
        if kind == "inbox" and row["to_role"] != actor_role:
            continue
        if actor_role == "Инженер" and (not actor_id or obj.get("responsible") != actor_id):
            continue
        visible.append(row.copy())
    if kind == "alerts":
        visible = [r for severity in ("CRITICAL", "STALE", "WARNING") for r in visible if r["severity"] == severity]
    return visible, None



def check_external_indicator(event, sites, seen):
    """Внешний вход с HMAC. Не вызывайте его как доверенный CSV."""
    return check_indicator(event, sites, seen, trusted_csv=False)


def edit_site(sites, site_id, name, zone, actor_role, audit=None, *, actor_zones=None):
    if actor_role != "Администратор":
        return False, api_error("FORBIDDEN")
    zones = DEFAULT_ZONES[actor_role] if actor_zones is None else actor_zones
    old_zone = sites.get(site_id, {}).get("zone")
    if zone not in zones or (old_zone and old_zone not in zones):
        return False, api_error("FORBIDDEN")
    if (not isinstance(site_id, str) or not re.fullmatch(r"site_[0-9]{2}", site_id)
            or zone not in ("zone_A", "zone_B", "zone_C") or not isinstance(name, str) or not name.strip()):
        return False, api_error("BAD_DATA")
    sites[site_id] = {"site_id": site_id, "name": name.strip(), "zone": zone}
    with open(SITES_STATE_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["site_id", "name", "zone"])
        writer.writeheader()
        writer.writerows(sites.values())
    audit_log(audit, "updated", actor_role, site_id, entity_type="site")
    return True, None


def notify(entity_type, entity_id, location, message, roles, sites, started=None):
    delay = (time.perf_counter() - started) * 1000 if started is not None else 0
    for role in roles:
        write_rows(INBOX_CSV, INBOX_FIELDS, [{"at": datetime.now(timezone.utc).isoformat(),
                   "entity_type": entity_type, "entity_id": entity_id, "location": location,
                   "zone": sites[location]["zone"], "to_role": role, "message": message,
                   "delivery_ms": round(delay, 3)}])


def report_sla(incidents, now, sites):
    overdue = find_sla_overdue(incidents, now)
    changed = False
    for item in overdue:
        original = next(r for r in incidents if r["incident_id"] == item["incident_id"])
        for reason in item["sla_breaches"].split(","):
            flag = reason + "_notified"
            if original.get(flag):
                continue
            roles = ["Диспетчер"] if item.get("severity") == "WARNING" else ["Руководитель"]
            notify("incident", item["incident_id"], item["location"], "SLA:" + reason, roles, sites)
            original[flag] = "yes"
            changed = True
    if changed:
        save_incidents()
    return overdue


def main():
    global RUN_INCIDENTS, INCIDENTS_CSV, INDICATORS_CSV
    incidents_path = INCIDENTS_CSV
    indicators_path = INDICATORS_CSV
    if "--incidents" in sys.argv:
        incidents_path = sys.argv[sys.argv.index("--incidents") + 1]
    if "--indicators" in sys.argv:
        indicators_path = sys.argv[sys.argv.index("--indicators") + 1]

    # справочник участков нужен для проверки location у показаний и инцидентов
    sites = load_sites()
    if not sites:
        print("❌ sites.csv пуст или не найден")
        sys.exit(2)

    if "--demo" in sys.argv:
        demo(sites)
        return

    if os.path.exists(OUT_CSV):
        with open(OUT_CSV, encoding="utf-8-sig") as f:
            if next(csv.reader(f), []) != OUT_FIELDS:
                print("alerts_out.csv от старой версии. Сохраните его отдельно и начните новый отчет.")
                return 2

    # Алерты и аудит сохраняют историю между запусками.
    # Повторное чтение CSV — отдельный прогон; счетчики ниже относятся к нему.

    with open(indicators_path, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    # правила окон (A-3, A-4, A-5) считаются в хронологическом порядке,
    # а в CSV строки идут не по времени
    ordered = []
    invalid_time = 0
    for index, row in enumerate(rows):
        try:
            ordered.append((parse_time(row["time"]), index, row))
        except (ValueError, TypeError, KeyError):
            invalid_time += 1
            print(api_error("BAD_DATA"))
    rows = [row for at, index, row in sorted(ordered)]

    PROCESSED_EVENTS.clear()
    INCIDENTS_CSV = incidents_path
    INDICATORS_CSV = indicators_path
    RUN_INCIDENTS = []
    RUN_INCIDENTS = load_incidents()
    seen = {}              # память по датчикам (см. new_state)
    ctx = {"alerts": 0, "duplicates": 0, "errors": 0, "stale_timeout": 0,
           "audit": [], "auto": [], "open_auto": {}}
    ctx["errors"] = invalid_time

    for incident in RUN_INCIDENTS:
        if incident.get("type") in ("temperature", "humidity", "ventilation") and incident.get("status") != "CLOSED":
            ctx["open_auto"][(incident["location"], incident["type"])] = incident

    # основной цикл: каждое показание проходит правила A-1…A-5
    for row in rows:
        ctx["started"] = time.perf_counter()
        try:
            now = parse_time(row["time"])
            flush_silent(ctx, sites, seen, now)
            results = check_indicator(row, sites, seen, trusted_csv=True)
            if not any(severity == "ERROR" for severity, action in results):
                ctx["measurement_id"] = "msr_" + uuid4().hex
                write_rows(MEASUREMENTS_CSV, MEASUREMENT_FIELDS,
                           [{**row, "measurement_id": ctx["measurement_id"],
                             "sensor_id": row["location"] + "/" + row["indicator"],
                             "status": calc_severity(row["value"], row["norm_min"], row["norm_max"])}])
        except (ValueError, KeyError) as e:
            print(f"❌ {row.get('location')} {row.get('time')}: BAD_DATA ({e})")
            ctx["errors"] += 1
            continue
        # одна строка может дать 0, 1 или 2 результата
        for severity, action in results:
            if severity == "ERROR":
                print(f"❌ {row['location']}: {api_error(action)}")
                ctx["errors"] += 1
                continue
            if severity == "DUPLICATE":
                ctx["duplicates"] += 1
                continue                      # второй алерт НЕ создаём
            emit_alert(ctx, sites, row["time"], row["location"], row["indicator"],
                       "" if severity == "STALE" else row["value"], severity, action)

    # A-4: после последней строки файла проверяем, кто замолчал больше чем на 5 минут
    end_time = max((parse_time(r["time"]) for r in rows), default=None)
    if end_time:
        flush_silent(ctx, sites, seen, end_time)

    with open(incidents_path, encoding="utf-8") as f:
        incs = list(csv.DictReader(f))

    # SLA закрытия: все инциденты (из CSV и созданные автоматически)
    overdue = report_sla(RUN_INCIDENTS, end_time, sites) if end_time else []
    if "--sla" in sys.argv:
        for i in overdue:
            print(f"[SLA] {i['incident_id']} ({i['status']}) просрочен: {i['sla_breaches']}")

    # сохраняем то, что раньше жило только в памяти
    # Аудит уже записан немедленно в audit_log().
    # Автоинциденты сохраняются сразу при создании.

    print()
    print(f"OK: indicators обработано: {len(rows)}")
    print(f"    алертов создано:       {ctx['alerts']}")
    print(f"    дубликатов пропущено:  {ctx['duplicates']}")
    print(f"    STALE по таймауту:     {ctx['stale_timeout']}")
    print(f"    автоинцидентов:        {len(ctx['auto'])}")
    print(f"    ошибок:                {ctx['errors']}")
    print(f"    incidents загружено:   {len(incs)}")
    print(f"    просрочено по SLA:     {len(overdue)}")
    print(f"    файлы: {OUT_CSV}")
    print(f"           {AUDIT_CSV}")
    print(f"           {AUTO_INCIDENTS_CSV}")


if __name__ == "__main__":
    sys.exit(main() or 0)
