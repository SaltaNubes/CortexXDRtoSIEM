#!/usr/bin/env python3
# Developed by Devel Security
# cjRAM
# Version 3.4.0 (TCP Added)
# Modificado para incluir integración con Wazuh, TCP y paginación.

import requests
from dotenv import load_dotenv
import os
import logging
import json
import socket
from datetime import datetime, timedelta
import time
import copy

# Cargar el archivo .env
load_dotenv()

# --- Configuración de variables de entorno ---
# Credenciales y Endpoints de Cortex XDR
fqdn = os.getenv("FQDN")
api_name1 = os.getenv("API_NAME1")
api_call1 = os.getenv("API_CALL1")
api_name2 = os.getenv("API_NAME2")
api_call2 = os.getenv("API_CALL2")
api_name3 = os.getenv("API_NAME3")
api_call3 = os.getenv("API_CALL3")
auth_id = os.getenv("AUTH_ID")
auth_key = os.getenv("AUTH_KEY")
time_offset_seconds = int(os.getenv("TIME_OFFSET_SECONDS", 300))
enable_audit = os.getenv("ENABLE_AUDIT", "false").lower() in ("1", "true", "yes", "on")

# Configuración de Syslog (UDP)
syslog_ip = os.getenv("SYSLOG_IP", "127.0.0.1")
syslog_port = int(os.getenv("SYSLOG_PORT", 514))
syslog_enabled = os.getenv("SYSLOG_ENABLED", "false").lower() == "true"

# --- NUEVO: Configuración de TCP ---
tcp_ip = os.getenv("TCP_IP", "127.0.0.1")
tcp_port = int(os.getenv("TCP_PORT", 514)) # Puerto común TCP puede ser 514, 601 o el que uses
tcp_enabled = os.getenv("TCP_ENABLED", "false").lower() == "true"

# Configuración de Wazuh
wazuh_socket_path = os.getenv("WAZUH_SOCKET_PATH", "/var/ossec/queue/sockets/queue")
wazuh_socket_enabled = os.getenv("WAZUH_SOCKET_ENABLED", "false").lower() == "true"

# --- Configuración de Tags para filtrar ---
filter_tags_str = os.getenv("FILTER_TAGS", "")
filter_tags = [tag.strip() for tag in filter_tags_str.split(',') if tag.strip()] if filter_tags_str else []

# Configuración de archivos de log de salida
ALERTS_LOG_FILE = os.getenv("ALERTS_LOG_FILE", "alerts.log")
AUDITS_LOG_FILE = os.getenv("AUDITS_LOG_FILE", "audits.log")
INCIDENTS_LOG_FILE = os.getenv("INCIDENTS_LOG_FILE", "incidents.log")
APP_LOG_FILE = os.getenv("APP_LOG_FILE", "cortex_xdr_app.log")

hostname = socket.gethostname()

# --- Configuración del logging ---
logging.basicConfig(
    filename=APP_LOG_FILE,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# --- URLs de la API ---
url1 = f"https://api-{fqdn}/public_api/v1/{api_name1}/{api_call1}/"
url2 = f"https://api-{fqdn}/public_api/v1/{api_name2}/{api_call2}/"
url3 = f"https://api-{fqdn}/public_api/v1/{api_name3}/{api_call3}/"

# --- Encabezados de la solicitud ---
headers = {
    "x-xdr-auth-id": str(auth_id),
    "Authorization": auth_key,
    "Content-Type": "application/json"
}

def calculate_gte():
    """Calcula el valor de 'gte'."""
    return int((datetime.now() - timedelta(seconds=time_offset_seconds)).timestamp() * 1000)

def fetch_all_results(url, payload, data_key, endpoint_name):
    """Obtiene todos los resultados usando paginación."""
    all_results = []
    search_from = 0
    page_size = 100
    base_payload = copy.deepcopy(payload)

    while True:
        request_payload = copy.deepcopy(base_payload)
        if endpoint_name in ['Alertas', 'Incidentes']:
            request_payload['request_data']['search_from'] = search_from
            request_payload['request_data']['search_to'] = search_from + page_size
            request_payload['request_data']['search_size'] = page_size
        elif endpoint_name == 'Eventos de Auditoría':
            request_payload['request_data']['from'] = search_from
            request_payload['request_data']['limit'] = page_size
        else:
            request_payload['request_data']['limit'] = page_size

        logging.debug(f"[{endpoint_name}] Obteniendo resultados desde {search_from}...")

        try:
            response = requests.post(url, headers=headers, json=request_payload)
            response.raise_for_status()
            response_data = response.json()

            if 'reply' not in response_data or not response_data['reply']:
                logging.warning(f"[{endpoint_name}] Respuesta vacía o sin 'reply'.")
                break

            results_on_page = response_data['reply'].get(data_key, [])
            total_count = response_data['reply'].get('total_count', 0)

            if not results_on_page:
                logging.info(f"[{endpoint_name}] No se encontraron más resultados.")
                break

            all_results.extend(results_on_page)
            logging.debug(f"[{endpoint_name}] Obtenidos {len(results_on_page)}. Total: {len(all_results)}/{total_count}.")

            if len(all_results) >= total_count:
                logging.debug(f"[{endpoint_name}] Todos los resultados obtenidos.")
                break

            search_from += page_size
            time.sleep(1)

        except Exception as e:
            logging.critical(f"[{endpoint_name}] Error: {e}")
            break

    return all_results

def filter_events_by_tags(events: list, required_tags: list) -> list:
    """Filtra eventos por tags."""
    if not required_tags:
        return events
    filtered = []
    for event in events:
        tags_str = event.get("original_tags", "")
        if not tags_str:
            continue
        tags = [tag.strip() for tag in tags_str.split(",")]
        if any(req in tags for req in required_tags):
            filtered.append(event)
    return filtered

def send_to_syslog(message_json):
    """Envía mensaje por UDP (Syslog standard)."""
    if not syslog_enabled:
        return
    try:
        message = f"{message_json}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode('utf-8'), (syslog_ip, syslog_port))
    except Exception as e:
        logging.error(f"Error UDP Syslog: {e}")

def send_to_tcp(message_json):
    """
    Envía mensaje por TCP.
    IMPORTANTE: Añade un salto de línea al final para separar eventos en el stream.
    """
    if not tcp_enabled:
        return
    try:
        # Añadimos \n porque TCP es un stream continuo
        message = f"{message_json}\n"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5) # Timeout de 5 segundos para evitar bloqueos
            sock.connect((tcp_ip, tcp_port))
            sock.sendall(message.encode('utf-8'))
    except socket.error as e:
        logging.error(f"Error de conexión TCP ({tcp_ip}:{tcp_port}): {e}")
    except Exception as e:
        logging.error(f"Error inesperado TCP: {e}")

def send_to_wazuh_socket(event_json):
    """Envía evento al socket Unix de Wazuh."""
    if not wazuh_socket_enabled:
        return
    try:
        wazuh_msg = f"1:CORTEX-XDR:cortex_xdr: {event_json}"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(wazuh_socket_path)
            sock.send(wazuh_msg.encode('utf-8'))
    except Exception as e:
        logging.error(f"Error Wazuh Socket: {e}")

def process_and_dispatch_events(events, log_file_path):
    """Escribe en archivo y envía a Syslog (UDP), TCP y Wazuh Socket."""
    with open(log_file_path, 'a', encoding='utf-8') as file:
        for event in events:
            event_json = json.dumps(event, ensure_ascii=False)
            
            # 1. Escribir en archivo local
            file.write(event_json + '\n')
            
            # 2. Enviar UDP
            send_to_syslog(event_json)
            
            # 3. Enviar TCP (NUEVO)
            send_to_tcp(event_json)
            
            # 4. Enviar Wazuh Socket
            send_to_wazuh_socket(event_json)

def main():
    """Función principal."""
    logging.info("Iniciando script Cortex XDR (v3.4.0 TCP).")
    gte_value = calculate_gte()

    # --- 1. Alertas ---
    payload_alerts = {
        "request_data": {
            "filters": [{"field": "creation_time", "operator": "gte", "value": gte_value}],
            "sort": {"field": "creation_time", "keyword": "asc"},
            "limit": 100
        }
    }
    all_alerts = fetch_all_results(url1, payload_alerts, 'alerts', 'Alertas')
    if all_alerts:
        logging.info(f"Alertas obtenidas: {len(all_alerts)}")
        
        filtered_alerts = filter_events_by_tags(all_alerts, filter_tags) if filter_tags else all_alerts
        
        if filtered_alerts:
            logging.info(f"Procesando {len(filtered_alerts)} alertas.")
            process_and_dispatch_events(filtered_alerts, ALERTS_LOG_FILE)
        else:
            logging.info("Alertas filtradas por tags: 0 coincidencias.")

    # --- 2. Auditoría ---
    if enable_audit:
        payload_audit = {
            "request_data": {
                "filters": [{"field": "timestamp", "operator": "gte", "value": gte_value}],
            }
        }
        all_audits = fetch_all_results(url2, payload_audit, 'data', 'Eventos de Auditoría')
        if all_audits:
            logging.info(f"Auditorías obtenidas: {len(all_audits)}")
            process_and_dispatch_events(all_audits, AUDITS_LOG_FILE)
    
    # --- 3. Incidentes ---
    payload_incidents = {
        "request_data": {
            "filters": [{"field": "creation_time", "operator": "gte", "value": gte_value}],
            "sort": {"field": "creation_time", "keyword": "asc"},
            "limit": 100
        }
    }
    all_incidents = fetch_all_results(url3, payload_incidents, 'incidents', 'Incidentes')
    if all_incidents:
        logging.info(f"Incidentes obtenidos: {len(all_incidents)}")
        
        filtered_incidents = filter_events_by_tags(all_incidents, filter_tags) if filter_tags else all_incidents
        
        if filtered_incidents:
            logging.info(f"Procesando {len(filtered_incidents)} incidentes.")
            process_and_dispatch_events(filtered_incidents, INCIDENTS_LOG_FILE)
        else:
            logging.info("Incidentes filtrados por tags: 0 coincidencias.")

    logging.info("Ejecución finalizada.")

if __name__ == "__main__":
    main()
