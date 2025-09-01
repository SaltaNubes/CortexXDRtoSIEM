#!/usr/bin/env python3
# Developed by Devel Security
# cjRAM
# Version 3.2.0
# Modificado para incluir integración con Wazuh y paginación para obtener todos los resultados.
# Modificado para leer los tags de filtrado desde el archivo .env

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
time_offset_seconds = int(os.getenv("TIME_OFFSET_SECONDS", 300))  # Aumentado para tener un margen mayor

# Configuración de Syslog
syslog_ip = os.getenv("SYSLOG_IP", "127.0.0.1")
syslog_port = int(os.getenv("SYSLOG_PORT", 514))
syslog_enabled = os.getenv("SYSLOG_ENABLED", "false").lower() == "true"

# Configuración de Wazuh
wazuh_socket_path = os.getenv("WAZUH_SOCKET_PATH", "/var/ossec/queue/sockets/queue")
wazuh_socket_enabled = os.getenv("WAZUH_SOCKET_ENABLED", "false").lower() == "true"

# --- NUEVO: Configuración de Tags para filtrar ---
# Los tags deben estar separados por comas en el archivo .env
filter_tags_str = os.getenv("FILTER_TAGS", "")
# Convertir el string de tags en una lista, eliminando espacios y entradas vacías
filter_tags = [tag.strip() for tag in filter_tags_str.split(',') if tag.strip()] if filter_tags_str else []


# Configuración de archivos de log de salida
ALERTS_LOG_FILE = os.getenv("ALERTS_LOG_FILE", "/opt/cortex_xdr_v3/alerts.log")
AUDITS_LOG_FILE = os.getenv("AUDITS_LOG_FILE", "/opt/cortex_xdr_v3/audits.log")
INCIDENTS_LOG_FILE = os.getenv("INCIDENTS_LOG_FILE", "/opt/cortex_xdr_v3/incidents.log")
APP_LOG_FILE = os.getenv("APP_LOG_FILE", "/opt/cortex_xdr_v3/cortex_xdr_app.log")

# Obtener el nombre del host para los logs
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
    """Calcula el valor de 'gte' como la fecha y hora actual menos el tiempo offset en segundos."""
    return int((datetime.now() - timedelta(seconds=time_offset_seconds)).timestamp() * 1000)

def fetch_all_results(url, payload, data_key, endpoint_name):
    """
    Obtiene todos los resultados de un endpoint de Cortex XDR usando paginación.
    - Alertas / Incidentes -> usan search_from, search_to y search_size.
    - Auditoría -> usa from + limit.
    """
    all_results = []
    search_from = 0
    page_size = 100  # tamaño máximo permitido por XDR
    base_payload = copy.deepcopy(payload)

    while True:
        request_payload = copy.deepcopy(base_payload)

        if endpoint_name in ['Alertas', 'Incidentes']:
            # offset-based pagination
            request_payload['request_data']['search_from'] = search_from
            request_payload['request_data']['search_to'] = search_from + page_size
            request_payload['request_data']['search_size'] = page_size

        elif endpoint_name == 'Eventos de Auditoría':
            # auditoría usa from + limit
            request_payload['request_data']['from'] = search_from
            request_payload['request_data']['limit'] = page_size

        else:
            # fallback genérico
            request_payload['request_data']['limit'] = page_size

        logging.info(f"[{endpoint_name}] Obteniendo resultados desde {search_from}...")

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
            logging.info(
                f"[{endpoint_name}] Obtenidos {len(results_on_page)} resultados. "
                f"Total acumulado: {len(all_results)} de {total_count}."
            )

            if len(all_results) >= total_count:
                logging.info(f"[{endpoint_name}] Se han obtenido todos los {total_count} resultados.")
                break

            # preparar siguiente página
            search_from += page_size
            time.sleep(1)

        except requests.exceptions.HTTPError as http_err:
            logging.critical(f"[{endpoint_name}] Error HTTP: {http_err} - Body: {http_err.response.text}")
            break
        except requests.exceptions.RequestException as req_err:
            logging.critical(f"[{endpoint_name}] Error de red o conexión: {req_err}")
            break
        except Exception as e:
            logging.critical(f"[{endpoint_name}] Error inesperado: {e}")
            break

    return all_results

def filter_events_by_tags(events: list, required_tags: list) -> list:
    """
    Filtra los eventos que contengan al menos uno de los tags exactos requeridos.

    :param events: Lista de eventos (dicts) que contienen el campo 'original_tags'.
    :param required_tags: Lista de tags a buscar (ej: ["ET:GYT_123", "EG:SG&T"]).
    :return: Lista de eventos que cumplen la condición.
    """
    if not required_tags:
        return events # Si no hay tags para filtrar, devuelve todos los eventos

    filtered = []
    for event in events:
        tags_str = event.get("original_tags", "")
        if not tags_str:
            continue
        
        tags = [tag.strip() for tag in tags_str.split(",")]  # separamos en tags exactos
        if any(req in tags for req in required_tags):        # coincidencia exacta
            filtered.append(event)
    return filtered

def send_to_syslog(message_json):
    """Envía un mensaje al servidor syslog si está activado."""
    if not syslog_enabled:
        return
    try:
        message = f"{message_json}"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(message.encode('utf-8'), (syslog_ip, syslog_port))
    except socket.error as e:
        logging.error(f"Error de socket al enviar a syslog ({syslog_ip}:{syslog_port}): {e}")
    except Exception as e:
        logging.error(f"Error inesperado al enviar a syslog: {e}")

def send_to_wazuh_socket(event_json):
    """Envía un evento al socket de Wazuh si está activado."""
    if not wazuh_socket_enabled:
        return
    try:
        wazuh_msg = f"1:CORTEX-XDR:cortex_xdr: {event_json}"
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(wazuh_socket_path)
            sock.send(wazuh_msg.encode('utf-8'))
    except socket.error as e:
        logging.error(f"Error al enviar evento al socket de Wazuh ({wazuh_socket_path}): {e}")
    except Exception as e:
        logging.error(f"Ocurrió un error inesperado al intentar enviar a Wazuh: {e}")

def process_and_dispatch_events(events, log_file_path):
    """Escribe cada evento en un archivo, lo envía a syslog y al socket de Wazuh."""
    with open(log_file_path, 'a', encoding='utf-8') as file:
        for event in events:
            event_json = json.dumps(event, ensure_ascii=False)
            file.write(event_json + '\n')
            send_to_syslog(event_json)
            send_to_wazuh_socket(event_json)

def main():
    """Función principal del script."""
    logging.info("Iniciando ejecución del script de Cortex XDR con paginación.")
    gte_value = calculate_gte()

    # --- 1. Obtener Alertas ---
    payload_alerts = {
        "request_data": {
            "filters": [{"field": "creation_time", "operator": "gte", "value": gte_value}],
            "sort": {"field": "creation_time", "keyword": "asc"},
            "limit": 100
        }
    }
    all_alerts = fetch_all_results(url1, payload_alerts, 'alerts', 'Alertas')
    if all_alerts:
        logging.info(f"Total de alertas obtenidas después de paginación: {len(all_alerts)}")

        # 🔎 Filtrar por tags si se han definido en .env
        if filter_tags:
            logging.info(f"Aplicando filtro de tags para alertas: {filter_tags}")
            filtered_alerts = filter_events_by_tags(all_alerts, filter_tags)
            logging.info(f"Total de alertas después de aplicar filtro: {len(filtered_alerts)}")
        else:
            logging.info("No se han configurado FILTER_TAGS, se procesarán todas las alertas.")
            filtered_alerts = all_alerts

        if filtered_alerts:
            process_and_dispatch_events(filtered_alerts, ALERTS_LOG_FILE)
        else:
            logging.info("No se encontraron alertas que coincidan con los tags requeridos.")


    # --- 2. Obtener Eventos de Auditoría ---
    payload_audit = {
        "request_data": {
            "filters": [{"field": "timestamp", "operator": "gte", "value": gte_value}],
        }
    }
    all_audits = fetch_all_results(url2, payload_audit, 'data', 'Eventos de Auditoría')
    if all_audits:
        logging.info(f"Total de eventos de auditoría obtenidos después de paginación: {len(all_audits)}")
        process_and_dispatch_events(all_audits, AUDITS_LOG_FILE)
    else:
        logging.info("No se encontraron nuevos eventos de auditoría o hubo un error al obtenerlos.")

    # --- 3. Obtener Incidentes ---
    payload_incidents = {
        "request_data": {
            "filters": [{"field": "creation_time", "operator": "gte", "value": gte_value}],
            "sort": {"field": "creation_time", "keyword": "asc"},
            "limit": 100
        }
    }
    all_incidents = fetch_all_results(url3, payload_incidents, 'incidents', 'Incidentes')
    if all_incidents:
        logging.info(f"Total de incidentes obtenidos después de paginación: {len(all_incidents)}")

        # 🔎 Filtrar por tags si se han definido en .env
        if filter_tags:
            logging.info(f"Aplicando filtro de tags para incidentes: {filter_tags}")
            filtered_incidents = filter_events_by_tags(all_incidents, filter_tags)
            logging.info(f"Total de incidentes después de aplicar filtro: {len(filtered_incidents)}")
        else:
            logging.info("No se han configurado FILTER_TAGS, se procesarán todos los incidentes.")
            filtered_incidents = all_incidents

        if filtered_incidents:
            process_and_dispatch_events(filtered_incidents, INCIDENTS_LOG_FILE)
        else:
            logging.info("No se encontraron incidentes que coincidan con los tags requeridos.")

    logging.info("Ejecución del script finalizada.")

if __name__ == "__main__":
    main()
