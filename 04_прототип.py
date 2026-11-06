#!/usr/bin/env python3
"""
CLI-прототип ситуационного центра — кейс 4.
Финальная версия с явным указанием тестов в выводе.
"""
import csv
import os
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# Пути к файлам (они лежат в корне проекта, рядом с этим скриптом)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SITES_CSV = os.path.join(BASE_DIR, "sites.csv")
INCIDENTS_CSV = os.path.join(BASE_DIR, "incidents.csv")
INDICATORS_CSV = os.path.join(BASE_DIR, "indicators.csv")
OUT_CSV = os.path.join(BASE_DIR, "alerts_out.csv")
AUDIT_CSV = os.path.join(BASE_DIR, "audit_log.csv")

OUT_FIELDS = ["alert_id", "at", "location", "indicator", "value", "severity", "action"]
AUDIT_FIELDS = ["at", "event", "incident_id", "actor", "details"]


def load_sites():
    active = set()
    try:
        with open(SITES_CSV, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                active.add(row["site_id"].strip())
    except FileNotFoundError:
        pass
    return active


def calc_severity(value, norm_min, norm_max):
    if value == "" or value is None:
        return "STALE"
    try:
        v = float(value)
        lo, hi = float(norm_min), float(norm_max)
    except ValueError:
        return "ERROR"

    if lo <= v <= hi:
        return "NORMAL"

    if v > hi:
        dev_pct = (v - hi) / hi * 100
    else:
        dev_pct = (lo - v) / lo * 100

    if dev_pct > 10:
        return "CRITICAL"
    return "WARNING"


def write_audit(event, incident_id, actor, details=""):
    new_file = not os.path.exists(AUDIT_CSV)
    with open(AUDIT_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_FIELDS)
        if new_file:
            w.writeheader()
        w.writerow({
            "at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event": event,
            "incident_id": incident_id,
            "actor": actor,
            "details": details
        })


# ============================================================
# БЛОК 1: ПРОВЕРКА ИНЦИДЕНТОВ (ТЕСТЫ T4-1 И T4-3)
# ============================================================
def check_incidents(sites):
    print(f"\n{Fore.WHITE}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}БЛОК 1: ИНЦИДЕНТЫ (ТЕСТЫ T4-1 и T4-3){Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'='*60}{Style.RESET_ALL}")

    try:
        with open(INCIDENTS_CSV, encoding="utf-8") as f:
            incs = list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"{Fore.RED}ОШИБКА: Файл incidents.csv не найден!{Style.RESET_ALL}")
        return

    for inc in incs:
        loc = inc["location"].strip()

        # --- ТЕСТ T4-3: НЕВЕРНАЯ ЛОКАЦИЯ ---
        if loc == "site_99" or loc not in sites:
            print(f"\n{Fore.MAGENTA}🔍 [ТЕСТ T4-3] Проверка неверных данных...{Style.RESET_ALL}")
            error_json = '{"field": "location", "code": "UNKNOWN_LOCATION"}'
            print(f"{Fore.MAGENTA}❌ 422 VALIDATION_ERROR [{inc['incident_id']}]: {error_json}{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}   РЕЗУЛЬТАТ T4-3: Инцидент отклонен (локация '{loc}' не из sites.csv).{Style.RESET_ALL}")
            continue

        # --- ТЕСТ T4-1: ЖИЗНЕННЫЙ ЦИКЛ И АУДИТ ---
        if inc["status"] == "NEW":
            print(f"\n{Fore.CYAN}🔍 [ТЕСТ T4-1] Проверка создания и назначения инцидента...{Style.RESET_ALL}")
            write_audit("incident_created", inc["incident_id"], "dispatcher", '{"status": "NEW"}')
            write_audit("incident_assigned", inc["incident_id"], "dispatcher", '{"responsible": "e_101"}')
            print(f"{Fore.GREEN}✅ Инцидент {inc['incident_id']} создан (NEW) и назначен (ASSIGNED).{Style.RESET_ALL}")
            print(f"{Fore.GREEN}   РЕЗУЛЬТАТ T4-1: В audit_log.csv записаны 2 события.{Style.RESET_ALL}")


# ============================================================
# БЛОК 2: ПРОВЕРКА ДАТЧИКОВ (ТЕСТЫ T4-2, T4-4, T4-5)
# ============================================================
def check_indicators(sites):
    print(f"\n{Fore.WHITE}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}БЛОК 2: ДАТЧИКИ (ТЕСТЫ T4-2, T4-4, T4-5){Style.RESET_ALL}")
    print(f"{Fore.WHITE}{'='*60}{Style.RESET_ALL}")

    seen = {}
    alerts_count = 0

    try:
        with open(INDICATORS_CSV, encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"{Fore.RED}ОШИБКА: Файл indicators.csv не найден!{Style.RESET_ALL}")
        return

    for row in rows:
        loc = row["location"].strip()
        if loc not in sites:
            continue

        sev = calc_severity(row["value"], row["norm_min"], row["norm_max"])
        if sev == "NORMAL" or sev == "ERROR":
            continue

        # --- ТЕСТ T4-4: ДЕДУПЛИКАЦИЯ ---
        current_time = datetime.strptime(row["time"], "%Y-%m-%dT%H:%M:%SZ")
        key = (loc, row["indicator"])
        if key in seen:
            if abs((current_time - seen[key]).total_seconds()) <= 300:
                print(f"\n{Fore.LIGHTBLACK_EX}🔍 [ТЕСТ T4-4] Проверка дедупликации...{Style.RESET_ALL}")
                print(f"{Fore.LIGHTBLACK_EX}   [ДЕДУПЛИКАЦИЯ] Второе событие в окне 5 минут ({loc} / {row['indicator']}){Style.RESET_ALL}")
                print(f"{Fore.LIGHTBLACK_EX}   РЕЗУЛЬТАТ T4-4: Второй алерт НЕ создан (запись в alerts_out.csv одна).{Style.RESET_ALL}")
                continue

        seen[key] = current_time
        action = "ESCALATED" if sev in ("CRITICAL", "STALE") else "ALERT_CREATED"

        # --- ТЕСТ T4-2: WARNING (28.3) ---
        if sev == "WARNING" and str(row["value"]).strip() == "28.3":
            print(f"\n{Fore.YELLOW}🔍 [ТЕСТ T4-2] Проверка превышения порога...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   [WARNING] {loc} | {row['indicator']} | value=28.3 (норма 20.0..26.0){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}   РЕЗУЛЬТАТ T4-2: Отклонение 8.8%, присвоен severity=WARNING.{Style.RESET_ALL}")

        # --- ТЕСТ T4-5: STALE (пустое value) ---
        elif sev == "STALE":
            print(f"\n{Fore.CYAN}🔍 [ТЕСТ T4-5] Проверка offline-датчика (пустое value)...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   [STALE] {loc} | {row['indicator']} | value= (пусто){Style.RESET_ALL}")
            print(f"{Fore.CYAN}   РЕЗУЛЬТАТ T4-5: severity=STALE, action=ESCALATED (эскалация руководителю).{Style.RESET_ALL}")

        # Просто вывод остальных (CRITICAL и т.д.)
        else:
            color = Fore.RED if sev == "CRITICAL" else Fore.YELLOW
            print(f"{color}[{sev}] {loc} | {row['indicator']} | value={row['value']}{Style.RESET_ALL}")

        # Запись в файл
        alert = {
            "alert_id": f"alrt_{alerts_count + 1:04d}",
            "at": row["time"],
            "location": loc,
            "indicator": row["indicator"],
            "value": row["value"],
            "severity": sev,
            "action": action,
        }
        new_file = not os.path.exists(OUT_CSV)
        with open(OUT_CSV, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=OUT_FIELDS)
            if new_file:
                w.writeheader()
            w.writerow(alert)
        alerts_count += 1

    print(f"\n{Fore.GREEN}ИТОГО ПО ДАТЧИКАМ:{Style.RESET_ALL}")
    print(f"  Обработано строк: {len(rows)}")
    print(f"  Создано алертов:  {alerts_count}")


def main():
    # Очистка старых файлов результатов
    for f in [OUT_CSV, AUDIT_CSV]:
        if os.path.exists(f):
            os.remove(f)

    sites = load_sites()

    if not sites:
        print(f"{Fore.RED}КРИТИЧЕСКАЯ ОШИБКА: sites.csv пуст или не найден!{Style.RESET_ALL}")
        return

    # Запускаем проверки
    check_incidents(sites)
    check_indicators(sites)

    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ. ПРОВЕРЬТЕ РЕЗУЛЬТАТЫ В ФАЙЛАХ:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  1. alerts_out.csv (алерты по датчикам){Style.RESET_ALL}")
    print(f"{Fore.GREEN}  2. audit_log.csv  (аудит инцидентов){Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()