# EDMC Plugin: EDFM Uploader
# Filename: load.py

import tkinter as tk
from tkinter import ttk
import tkinter.filedialog
import json
import shutil
import os
import pathlib
import threading
import logging
import webbrowser
import queue
import time
from datetime import datetime
from typing import Optional, Dict, Any, List  # Added Optional, Dict, Any, List

PLUGIN_NAME = "EDFM Uploader"
PLUGIN_VERSION = "1.4.1"  # Incremented for enhanced logging
PLUGIN_DESCRIPTION = "Sends data to EDFM."

# Get the root directory where `load.py` is located
root_dir = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(root_dir, f"{PLUGIN_NAME.replace(' ', '_')}.log")

# Configure the logger
plugin_logger = logging.getLogger(f"EDMC.{PLUGIN_NAME}")
# Ensure logger is not doubly configured if EDMC sets it up
if not plugin_logger.handlers:
    plugin_logger.setLevel(logging.DEBUG)  # Set the desired log level

    # Create a file handler for logging
    file_handler = logging.FileHandler(log_file_path, encoding='utf-8')  # Append mode
    file_handler.setLevel(logging.DEBUG)  # Log all messages (DEBUG and above)

    # Create a formatter and set it for the file handler
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(module)s:%(lineno)d - %(message)s')
    file_handler.setFormatter(formatter)

    # Add the file handler to the logger
    plugin_logger.addHandler(file_handler)

try:
    import myNotebook as nb  # type: ignore

    NB_FRAME_CLASS = nb.Frame
    plugin_logger.info("myNotebook imported successfully, using nb.Frame.")
except ImportError:
    plugin_logger.warning("Failed to import myNotebook. Using ttk.Frame as fallback for UI.")
    NB_FRAME_CLASS = ttk.Frame  # type: ignore

try:
    import requests
except ImportError:
    requests = None  # type: ignore
    plugin_logger.error("The 'requests' library is not installed. This plugin will not be able to send data.")

CONFIG_API_KEY = "edfm_ApiKey"
CONFIG_SEND_CONSTRUCTION_DATA = "edfm_SendConstruction"
CONFIG_SEND_COMMANDER_STATUS = "edfm_SendCommanderStatus"
CONFIG_SEND_MARKET_DATA = "edfm_SendMarketData"

BASE_API_URL = "https://edfm.space/api/v1"


CONSTRUCTION_API_URL = "f{BASE_API_URL}/construction_update"
COMMANDER_STATUS_API_URL = "f{BASE_API_URL}/commander_status"
MARKET_DATA_API_URL = "f{BASE_API_URL}/market_data"
PLAYER_CONSTRUCTION_CONTRIBUTION_URL = f"{BASE_API_URL}/log_player_construction_delivery"
GALNET_URL = "https://edfm.space/galnet"
CONSTRUCTION_PAGE_PATH = "/construction"
LOGIN_PAGE_PATH = "/login"

QUEUE_SHUTDOWN_SIGNAL = "ShutdownSignal"  # Constant for the queue shutdown signal

this_config = None
plugin_session = None
event_queue = queue.Queue()  # type: ignore
worker_thread = None
last_known_cargo: None
last_known_market_data: {}


def _get_edmc_log_file_path(logger_to_use_for_messages: logging.Logger) -> Optional[str]:
    """
    Tries to find the EDMC main log file by checking common logger configurations and fallback paths.
    """
    # Priority 1: "EDMC" logger's FileHandler
    edmc_specific_logger = logging.getLogger("EDMC")
    for handler in edmc_specific_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            log_path = handler.baseFilename
            logger_to_use_for_messages.info(f"Found EDMC log file via 'EDMC' logger handler: {log_path}")
            return log_path

    # Priority 2: Root logger's FileHandler
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if isinstance(handler, logging.FileHandler):
            # Heuristic: Avoid picking up this plugin's own log file
            if PLUGIN_NAME.replace(' ', '_') not in handler.baseFilename:
                log_path = handler.baseFilename
                logger_to_use_for_messages.info(f"Found EDMC log file via root logger handler: {log_path}")
                return log_path
            else:
                logger_to_use_for_messages.debug(f"Skipping own log file found on root logger: {handler.baseFilename}")

    # Priority 3: Fallback to scanning TEMP directory
    temp_dir = os.getenv('TEMP', os.getenv('TMP', os.path.expanduser('~')))
    possible_log_names = ['EDMarketConnector.log', 'EDMC.log']
    for log_name in possible_log_names:
        potential_path = os.path.join(temp_dir, log_name)
        if os.path.exists(potential_path):
            logger_to_use_for_messages.warning(f"Found EDMC log file via fallback temp path: {potential_path}")
            return potential_path

    logger_to_use_for_messages.error(
        "Could not determine EDMC log file path. Checked 'EDMC' logger, root logger, and common temp locations."
    )
    return None


class ConfigDialog:
    def __init__(self, parent_frame_for_tab, config_obj):
        plugin_logger.debug(f"[{PLUGIN_NAME}] ConfigDialog.__init__ called.")
        self.parent_frame = parent_frame_for_tab
        self.config = config_obj
        self.status_label_widget = None

        self.parent_frame.columnconfigure(0, weight=1)

        try:
            # API Key Configuration
            api_frame = ttk.LabelFrame(self.parent_frame, text="API Configuration", padding="10")
            api_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
            self.api_key_var = tk.StringVar(value=self.config.get_str(CONFIG_API_KEY, default=""))
            ttk.Label(api_frame, text="Your API Key:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
            self.api_key_entry = ttk.Entry(api_frame, textvariable=self.api_key_var, width=50, show="*")
            self.api_key_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
            self.show_api_key_var = tk.BooleanVar()
            self.show_api_key_check = ttk.Checkbutton(api_frame, text="Show API Key", variable=self.show_api_key_var,
                                                      command=self._toggle_api_key_visibility)
            self.show_api_key_check.grid(row=1, column=1, padx=5, pady=2, sticky="w")
            api_frame.columnconfigure(1, weight=1)

            # Data Sending Preferences
            prefs_frame = ttk.LabelFrame(self.parent_frame, text="Data Sending Preferences", padding="10")
            prefs_frame.grid(row=1, column=0, sticky="ew", padx=5, pady=10)
            self.send_construction_var = tk.BooleanVar(
                value=self.config.get_bool(CONFIG_SEND_CONSTRUCTION_DATA, default=True))
            ttk.Checkbutton(prefs_frame, text="Send Colonisation Construction Data (Station Totals & Contributions)",
                            variable=self.send_construction_var).pack(anchor="w", padx=5, pady=2)
            self.send_commander_status_var = tk.BooleanVar(
                value=self.config.get_bool(CONFIG_SEND_COMMANDER_STATUS, default=True))
            ttk.Checkbutton(prefs_frame, text="Send Commander Status (Location, Credits, Cargo, etc.)",
                            variable=self.send_commander_status_var).pack(anchor="w", padx=5, pady=2)
            self.send_market_data_var = tk.BooleanVar(value=self.config.get_bool(CONFIG_SEND_MARKET_DATA, default=True))
            ttk.Checkbutton(prefs_frame, text="Send Market Data (from Market.json)",
                            variable=self.send_market_data_var).pack(anchor="w", padx=5, pady=2)

            # Information & Links & Utilities Section
            info_frame = ttk.LabelFrame(self.parent_frame, text="Faction Resources & Utilities", padding="10")
            info_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=10)
            ttk.Label(info_frame, text="Ensure you have the correct API key configured above.").pack(pady=(0, 5),
                                                                                                     anchor="w")

            galnet_link = ttk.Label(info_frame, text="View EDFM GalNet Feed", foreground="blue", cursor="hand2")
            galnet_link.pack(pady=5, anchor="w")
            galnet_link.bind("<Button-1>", lambda ex: webbrowser.open_new_tab(GALNET_URL))

            construction_link = ttk.Label(info_frame, text="View Active Constructions", foreground="blue",
                                          cursor="hand2")
            construction_link.pack(pady=5, anchor="w")
            construction_base_url = GALNET_URL.replace("/galnet", "")  # Assumes GALNET_URL ends with /galnet
            construction_link.bind("<Button-1>", lambda ex: webbrowser.open_new_tab(
                f"{construction_base_url}{CONSTRUCTION_PAGE_PATH}"))

            ttk.Label(info_frame, text="To get an API key, signup on the fleetmanager app.").pack(pady=(10, 0),
                                                                                                  anchor="w")
            api_link = ttk.Label(info_frame, text="Get an API-Key", foreground="blue", cursor="hand2")
            api_link.pack(pady=(0, 5), anchor="w")
            api_link.bind("<Button-1>", lambda ex: webbrowser.open_new_tab(f"{construction_base_url}{LOGIN_PAGE_PATH}"))

            ttk.Button(info_frame, text="Save Debug Log", command=self._save_debug_log).pack(pady=(10, 5), anchor="w")

            # Save Button (row 3)
            save_button = ttk.Button(self.parent_frame, text="Save Settings", command=self._save_config)
            save_button.grid(row=3, column=0, pady=20)

            self.api_key_entry.focus_set()
            plugin_logger.info(f"[{PLUGIN_NAME}] ConfigDialog initialized successfully.")

        except Exception as e:
            plugin_logger.error(f"[{PLUGIN_NAME}] Error during ConfigDialog.__init__: {e}", exc_info=True)
            error_label = ttk.Label(self.parent_frame,
                                    text=f"Error building settings UI: {e}\nCheck EDMC logs for details.")
            error_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
            self.parent_frame.rowconfigure(0, weight=1)

    def _toggle_api_key_visibility(self):
        self.api_key_entry.config(show="" if self.show_api_key_var.get() else "*")

    def _save_config(self):
        try:
            self.config.set(CONFIG_API_KEY, self.api_key_var.get().strip())
            self.config.set(CONFIG_SEND_CONSTRUCTION_DATA, self.send_construction_var.get())
            self.config.set(CONFIG_SEND_COMMANDER_STATUS, self.send_commander_status_var.get())
            self.config.set(CONFIG_SEND_MARKET_DATA, self.send_market_data_var.get())
            plugin_logger.info("Configuration saved.")
            self._show_status_message("Settings saved!")
        except Exception as e:
            plugin_logger.error(f"Error saving config: {e}", exc_info=True)
            self._show_status_message(f"Error saving: {e}", "red")

    def _show_status_message(self, message, color="green", duration=3000):
        if self.status_label_widget and self.status_label_widget.winfo_exists():
            self.status_label_widget.destroy()

        # Place status label consistently at row 4, assuming Save button is at row 3
        status_label_row = 4
        self.status_label_widget = ttk.Label(self.parent_frame, text=message, foreground=color)
        self.status_label_widget.grid(row=status_label_row, column=0, pady=(0, 10), sticky="ew")  # Adjusted padding

        # Use parent_frame.after for scheduling destruction
        self.parent_frame.after(duration,
                                lambda: self.status_label_widget.destroy() if self.status_label_widget and self.status_label_widget.winfo_exists() else None)

    def _save_debug_log(self):
        plugin_logger.info("Attempting to save debug log...")
        edmc_log_path = _get_edmc_log_file_path(plugin_logger)

        if not edmc_log_path or not os.path.exists(edmc_log_path):
            plugin_logger.error(f"EDMC log file not found or path indeterminate. Searched path: {edmc_log_path}")
            self._show_status_message("Error: EDMC log file not found.", "red")
            return

        default_filename = f"{PLUGIN_NAME.replace(' ', '_')}_debug_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        save_path = tkinter.filedialog.asksaveasfilename(initialfile=default_filename, defaultextension=".log",
                                                         filetypes=[("Log files", "*.log"), ("Text files", "*.txt"),
                                                                    ("All files", "*.*")])
        if not save_path:
            plugin_logger.info("Save debug log cancelled by user.")
            return
        try:
            with open(save_path, 'w', encoding='utf-8') as f_out:
                f_out.write(
                    f"--- {PLUGIN_NAME} Debug Information ---\nPlugin Version: {PLUGIN_VERSION}\nLog Saved: {datetime.now().isoformat()}\n")
                f_out.write(
                    f"API Key Configured: {'Yes' if self.api_key_var.get() else 'No'}\nSend Construction Data: {self.send_construction_var.get()}\n")
                f_out.write(
                    f"Send Commander Status: {self.send_commander_status_var.get()}\nSend Market Data: {self.send_market_data_var.get()}\n")
                f_out.write(f"Original EDMC Log Path: {edmc_log_path}\n--- End of Plugin Debug Information ---\n\n")
                with open(edmc_log_path, encoding='utf-8', errors='replace') as f_in:
                    shutil.copyfileobj(f_in, f_out)
            plugin_logger.info(f"Debug log saved successfully to: {save_path}")
            self._show_status_message(f"Debug log saved to:\n{os.path.basename(save_path)}", duration=5000)
        except Exception as e:
            plugin_logger.error(f"Error saving debug log: {e}", exc_info=True)
            self._show_status_message(f"Error saving debug log: {e}", "red")


def _create_log_identifier(data_type: str, payload: Optional[dict]) -> str:
    """Helper to create a concise log identifier for an event."""
    parts = [data_type]
    if payload:
        event_val = payload.get('event_type', payload.get('event'))
        if event_val:
            parts.append(f"Event: {event_val}")
        if 'MarketID' in payload:
            parts.append(f"MktID: {payload['MarketID']}")
    identifier = ", ".join(filter(None, parts))
    return identifier or "UnknownEvent"


def send_data_worker():
    max_retries = 3
    retry_delay_seconds = 10
    global plugin_session  # No need for log_identifier here

    while True:
        target_url, api_key, data_type, payload = None, None, None, None
        try:
            target_url, api_key, data_type, payload = event_queue.get()
            if target_url is None and data_type == QUEUE_SHUTDOWN_SIGNAL:  # Use constant
                plugin_logger.info("Send worker thread: Stop signal received.")
                break
            if not plugin_session:
                plugin_logger.error(f"Send worker ({data_type}): Requests session not initialized. Skipping event.")
                event_queue.task_done()
                continue

            headers = {'X-API-Key': api_key, 'Content-Type': 'application/json',
                       'User-Agent': f"{PLUGIN_NAME}/{PLUGIN_VERSION}"}

            for attempt in range(max_retries):
                try:
                    log_identifier = _create_log_identifier(data_type, payload)  # Use helper
                    plugin_logger.info(
                        f"Send worker: Attempt {attempt + 1}/{max_retries} for {log_identifier} to {target_url}")

                    response = plugin_session.post(target_url, json=payload, headers=headers, timeout=20)
                    response.raise_for_status()

                    try:
                        response_json = response.json()
                        if isinstance(response_json, dict) and response_json.get('status') == 'error':
                            plugin_logger.warning(
                                f"API error for {log_identifier}: {response_json.get('message', 'No message')}.")
                        else:
                            plugin_logger.info(f"Data sent successfully by worker for {log_identifier}.")
                    except ValueError:  # Handles cases like empty response or non-JSON response
                        plugin_logger.info(
                            f"Data sent (non-JSON/empty response) for {log_identifier}. Status: {response.status_code}")
                    break  # Success, break from retry loop
                except requests.exceptions.HTTPError as http_err:
                    plugin_logger.error(
                        f"Send worker: HTTP error (attempt {attempt + 1}) for {log_identifier}: {http_err}")
                    if http_err.response is not None and 400 <= http_err.response.status_code < 500:
                        plugin_logger.warning(
                            f"Send worker: Client error {http_err.response.status_code} for {log_identifier}. Not retrying.")
                        break  # Client error, don't retry
                except requests.exceptions.RequestException as req_err:
                    plugin_logger.error(
                        f"Send worker: Request exception (attempt {attempt + 1}) for {log_identifier}: {req_err}")

                if attempt + 1 < max_retries:
                    plugin_logger.info(f"Send worker: Retrying {log_identifier} in {retry_delay_seconds} seconds...")
                    time.sleep(retry_delay_seconds)
                else:
                    plugin_logger.error(f"Send worker: Max retries for {log_identifier}. Giving up.")
        except queue.Empty:  # Should not happen with blocking get(), but good practice
            time.sleep(0.1)
        except Exception as e:
            dt_info = data_type if data_type else "N/A"
            pl_info = str(payload)[:100] if payload else "N/A"  # Limit payload log size
            plugin_logger.error(f"Send worker thread ({dt_info}): Unexpected error. Payload: {pl_info}. Error: {e}",
                                exc_info=True)
            if target_url is None and data_type == QUEUE_SHUTDOWN_SIGNAL:  # Use constant
                plugin_logger.critical("Send worker: Error while processing ShutdownSignal. Forcing break.")
                break  # Ensure shutdown signal processing error doesn't loop indefinitely
        finally:
            if 'event_queue' in locals() and hasattr(event_queue, 'task_done'):  # Ensure event_queue is defined
                event_queue.task_done()


def plugin_start3(plugin_dir):
    global this_config, plugin_session, worker_thread, last_known_cargo, last_known_market_data
    try:
        from config import config as edmc_global_config
        this_config = edmc_global_config
        plugin_logger.info(f"[{PLUGIN_NAME}] plugin_start3: this_config {'is SET' if this_config else 'is NONE'}")

        last_known_cargo = None
        last_known_market_data = {}

        if not requests:
            plugin_logger.critical("Requests library not available. Plugin disabled.")
            return None  # Plugin cannot run

        if plugin_session is None:
            plugin_session = requests.Session()

        if worker_thread is None or not worker_thread.is_alive():
            worker_thread = threading.Thread(target=send_data_worker, name=f"{PLUGIN_NAME}SendWorker", daemon=True)
            worker_thread.start()
            plugin_logger.info(f"{PLUGIN_NAME} v{PLUGIN_VERSION} started. Worker thread active.")
        else:
            plugin_logger.info(f"{PLUGIN_NAME} v{PLUGIN_VERSION} re-confirmed (worker already alive).")

    except ImportError:
        plugin_logger.critical("Failed to import EDMC's global 'config' module. Plugin cannot initialize.")
        this_config = None
        return None
    except Exception as e:
        plugin_logger.critical(f"Unexpected error during plugin_start3: {e}", exc_info=True)
        this_config = None
        return None

    return PLUGIN_NAME


def plugin_stop():
    global worker_thread, plugin_session
    plugin_logger.info(f"{PLUGIN_NAME} v{PLUGIN_VERSION} stopping...")
    if worker_thread and worker_thread.is_alive():
        event_queue.put((None, None, QUEUE_SHUTDOWN_SIGNAL, None))  # Use constant
        worker_thread.join(timeout=5)  # Wait for the thread to finish
        if worker_thread.is_alive():
            plugin_logger.warning("Worker thread did not stop in time.")
        else:
            plugin_logger.info("Worker thread stopped.")
    worker_thread = None

    if plugin_session:
        plugin_session.close()
        plugin_session = None
        plugin_logger.info("Requests session closed.")
    plugin_logger.info(f"{PLUGIN_NAME} stopped.")


def plugin_prefs(parent_notebook, cmdr, is_beta):
    plugin_logger.info(f"[{PLUGIN_NAME}] plugin_prefs called. Commander: {cmdr}, IsBeta: {is_beta}")
    plugin_logger.info(
        f"[{PLUGIN_NAME}] Current this_config status in plugin_prefs: {'SET' if this_config else 'NOT SET'}")

    try:
        tab_frame = NB_FRAME_CLASS(parent_notebook)
        parent_notebook.add(tab_frame, text=PLUGIN_NAME)
        plugin_logger.debug(f"[{PLUGIN_NAME}] Tab frame created and added to notebook.")
        tab_frame.columnconfigure(0, weight=1)  # Ensure content can expand
    except Exception as e:
        plugin_logger.error(f"[{PLUGIN_NAME}] CRITICAL: Failed to create or add tab_frame to notebook: {e}",
                            exc_info=True)
        # Attempt to add an error message tab if primary tab creation fails
        try:
            emergency_frame = ttk.Frame(parent_notebook)
            parent_notebook.add(emergency_frame, text=f"{PLUGIN_NAME} (Error)")
            ttk.Label(emergency_frame, text=f"Failed to create plugin tab: {e}").pack(fill=tk.BOTH, expand=True)
            return emergency_frame
        except Exception as emergency_e:  # Catch error during emergency frame creation
            plugin_logger.error(f"[{PLUGIN_NAME}] CRITICAL: Failed to create emergency error tab: {emergency_e}",
                                exc_info=True)
            return None  # Cannot create any UI

    if this_config is None:
        plugin_logger.error(f"[{PLUGIN_NAME}] this_config is None in plugin_prefs. Displaying error message.")
        error_label = ttk.Label(tab_frame,
                                text="Error: Plugin configuration system not loaded.\nPlease restart EDMC or check logs.")
        error_label.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        tab_frame.rowconfigure(0, weight=1)  # Ensure error label expands
        return tab_frame

    try:
        plugin_logger.debug(f"[{PLUGIN_NAME}] Instantiating ConfigDialog.")
        ConfigDialog(tab_frame, this_config)
        plugin_logger.debug(f"[{PLUGIN_NAME}] ConfigDialog instantiation apparently successful.")
    except Exception as e:
        plugin_logger.error(f"[{PLUGIN_NAME}] Error creating ConfigDialog UI: {e}", exc_info=True)
        error_label_ui = ttk.Label(tab_frame, text=f"Error loading settings UI: {e}.\nCheck EDMC logs for details.")
        error_label_ui.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        tab_frame.rowconfigure(0, weight=1)  # Ensure error label expands

    return tab_frame


# --- Journal Event Handling Helper Functions ---

def _handle_construction_event(entry: Dict[str, Any], api_key: str, system: Optional[str], station: Optional[str],
                               event_name: str):
    """Handles TechnologyBroker and ColonisationConstructionDepot events."""
    if not this_config.get_bool(CONFIG_SEND_CONSTRUCTION_DATA, default=True):
        return

    plugin_logger.info(f"Processing '{event_name}' event. Full entry data: {json.dumps(entry, indent=2)}")

    payload = entry.copy()
    # Ensure StarSystem and StationName are present if possible
    if 'SystemName' in payload and 'StarSystem' not in payload:
        payload['StarSystem'] = payload.pop('SystemName')
    elif 'StarSystem' not in payload and system:
        payload['StarSystem'] = system

    if 'StationName' not in payload and station:
        payload['StationName'] = station

    if not payload.get('MarketID'):
        plugin_logger.warning(
            f"Skipping {event_name} for {payload.get('StationName', 'Unknown Station')} as MarketID is missing.")
        return

    plugin_logger.info(
        f"Queuing ConstructionUpdate for MarketID {payload.get('MarketID')} from {event_name}. Payload: {json.dumps(payload, indent=2)}")
    try:
        event_queue.put((CONSTRUCTION_API_URL, api_key, "ConstructionUpdate", payload))
    except Exception as e:
        plugin_logger.error(f"Failed to queue ConstructionUpdate: {e}", exc_info=True)


def _handle_market_data_event(entry: Dict[str, Any], api_key: str, system: Optional[str], station: Optional[str],
                              timestamp: str):
    """Handles Market event and processes Market.json."""
    global last_known_market_data
    if not this_config.get_bool(CONFIG_SEND_MARKET_DATA, default=True):
        return

    market_id = entry.get('MarketID')
    if not market_id:
        plugin_logger.warning("Market event received, but it's missing MarketID. Cannot process Market.json.")
        return

    journal_dir_path_str = this_config.get_str("journaldir") or this_config.default_journal_dir
    if not journal_dir_path_str:
        plugin_logger.error("Journal directory not configured in EDMC. Cannot read Market.json.")
        return

    market_json_path = pathlib.Path(journal_dir_path_str) / "Market.json"
    try:
        if not market_json_path.exists():
            plugin_logger.warning(f"Market.json not found at expected path: {market_json_path}")
            return

        with open(market_json_path, encoding='utf-8') as f:
            market_file_data = json.load(f)

        if market_file_data.get('MarketID') != market_id:
            plugin_logger.warning(
                f"Market.json MarketID ({market_file_data.get('MarketID')}) does not match current Market event MarketID ({market_id}). Stale file?")
            return

        current_market_commodities = []
        if 'Items' in market_file_data:
            for item in market_file_data['Items']:
                category_value = item.get("Category")
                category_name = "N/A"
                if isinstance(category_value, dict):  # Check if Category is a dict (newer format)
                    category_name = category_value.get("Name", "N/A")
                elif isinstance(category_value, str):  # Fallback for older format or if Category_Localised is preferred
                    category_name = item.get("Category_Localised", category_value)

                current_market_commodities.append({
                    "Name": item.get("Name", "N/A"), "Name_Localised": item.get("Name_Localised"),
                    "Category": category_name, "BuyPrice": item.get("BuyPrice", 0),
                    "SellPrice": item.get("SellPrice", 0), "MeanPrice": item.get("MeanPrice", 0),
                    "StockBracket": item.get("StockBracket", 0), "DemandBracket": item.get("DemandBracket", 0),
                    "Stock": item.get("Stock", 0), "Demand": item.get("Demand", 0),
                    "Consumer": item.get("Consumer", False), "Producer": item.get("Producer", False),
                    "Rare": item.get("Rare", False)
                })
            current_market_commodities.sort(key=lambda x: x["Name"])

        if current_market_commodities != last_known_market_data.get(market_id):
            market_payload = {
                "event_type": "MarketDataUpdate",
                "timestamp": market_file_data.get("timestamp", timestamp),  # Prefer Market.json timestamp
                "MarketID": market_id,
                "StarSystem": market_file_data.get("StarSystem", system),
                "StationName": market_file_data.get("StationName", station),
                "StationType": market_file_data.get("StationType"),
                "CarrierDockingAccess": market_file_data.get("CarrierDockingAccess"),
                "Items": current_market_commodities
            }
            event_queue.put((MARKET_DATA_API_URL, api_key, "MarketDataUpdate", market_payload))
            plugin_logger.info(
                f"Queued MarketDataUpdate for MktID {market_id} ({len(current_market_commodities)} items)")
            last_known_market_data[market_id] = current_market_commodities
        else:
            plugin_logger.info(f"Market data for MktID {market_id} unchanged. Not sending.")
    except json.JSONDecodeError as jde:
        plugin_logger.error(f"Failed to decode Market.json for MktID {market_id}: {jde}", exc_info=True)
    except Exception as e:
        plugin_logger.error(f"Failed to process Market.json for MktID {market_id}: {e}", exc_info=True)


# --- Commander Status Event Payload Builders ---
def _build_loadgame_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "LoadGame", "credits": entry.get('Credits'),
            "gameMode": entry.get('GameMode'), "ship": entry.get('Ship'), "shipID": entry.get('ShipID'),
            "shipName": entry.get('ShipName'), "shipIdent": entry.get('ShipIdent'),
            "fuelLevel": entry.get('FuelLevel'), "fuelCapacity": entry.get('FuelCapacity')}


def _build_location_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "LocationUpdate", "systemName": entry.get('StarSystem'),
            "starPos": entry.get('StarPos'), "body": entry.get('Body'), "bodyType": entry.get('BodyType'),
            "docked": entry.get('Docked', False),
            "stationName": entry.get('StationName') if entry.get('Docked') else None,
            "stationType": entry.get('StationType') if entry.get('Docked') else None,
            "marketID": entry.get('MarketID') if entry.get('Docked') else None,
            "onFoot": entry.get('OnFoot', False)}


def _build_fsdjump_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "FSDJump", "StarSystem": entry.get('StarSystem'),
            "starPos": entry.get('StarPos'), "jumpDist": entry.get('JumpDist'),
            "fuelUsed": entry.get('FuelUsed'), "fuelLevel": entry.get('FuelLevel')}


def _build_docked_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "Docked", "StarSystem": entry.get('StarSystem'),
            "StationName": entry.get('StationName'), "StationType": entry.get('StationType'),
            "MarketID": entry.get('MarketID')}


def _build_undocked_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "Undocked", "StationName": entry.get('StationName')}


def _build_carrierjump_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "CarrierJump", "StarSystem": entry.get('StarSystem'),
            "Body": entry.get('Body'), "BodyID": entry.get('BodyID'),
            "SystemAddress": entry.get('SystemAddress'), "Docked": entry.get('Docked', False),
            "StationName": entry.get('StationName'), "MarketID": entry.get('MarketID')}


def _build_statistics_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "StatisticsUpdate",
            "Bank_Account": {"Current_Wealth": entry.get('Bank_Account', {}).get('Current_Wealth')}}


def _build_embark_disembark_payload(entry: Dict[str, Any], base_payload: Dict[str, Any], event_name: str) -> Dict[
    str, Any]:
    return {**base_payload, "event_type": event_name, "SRV": entry.get('SRV', False),
            "Taxi": entry.get('Taxi', False), "Multicrew": entry.get('Multicrew', False),
            "OnStation": entry.get('OnStation', False), "OnPlanet": entry.get('OnPlanet', False),
            "StationName": entry.get('StationName'), "StationType": entry.get('StationType'),
            "Body": entry.get('Body'), "BodyID": entry.get('BodyID'), "ID": entry.get('ID')}


def _build_shutdown_payload(entry: Dict[str, Any], base_payload: Dict[str, Any]) -> Dict[str, Any]:
    return {**base_payload, "event_type": "Shutdown"}


COMMANDER_EVENT_PAYLOAD_BUILDERS = {
    'LoadGame': _build_loadgame_payload,
    'Location': _build_location_payload,
    'FSDJump': _build_fsdjump_payload,
    'Docked': _build_docked_payload,
    'Undocked': _build_undocked_payload,
    'CarrierJump': _build_carrierjump_payload,
    'Statistics': _build_statistics_payload,
    'Embark': lambda e, bp: _build_embark_disembark_payload(e, bp, 'Embark'),
    'Disembark': lambda e, bp: _build_embark_disembark_payload(e, bp, 'Disembark'),
    'Shutdown': _build_shutdown_payload,
}


def _handle_commander_status_events(entry: Dict[str, Any], api_key: str, cmdr: str, state: Dict[str, Any],
                                    timestamp: str, event_name: str):
    """Handles various commander status events using a dispatcher."""
    if not this_config.get_bool(CONFIG_SEND_COMMANDER_STATUS, default=True):
        return

    base_payload = {"timestamp": timestamp, "commanderName": cmdr, "commanderFID": state.get('FID')}
    payload_builder = COMMANDER_EVENT_PAYLOAD_BUILDERS.get(event_name)

    if payload_builder:
        payload = payload_builder(entry, base_payload)
        if payload:
            # Use event_type from payload for logging, fallback to original event_name
            data_type_log_name = payload.get("event_type", event_name)
            try:
                event_queue.put((COMMANDER_STATUS_API_URL, api_key, f"CommanderStatus_{data_type_log_name}", payload))
                plugin_logger.info(f"Queued CommanderStatus_{data_type_log_name}")
            except Exception as e:
                plugin_logger.error(f"Failed to queue CommanderStatus_{data_type_log_name}: {e}", exc_info=True)


CARGO_TRIGGER_EVENTS = [
    'Cargo', 'LoadGame', 'Docked', 'Undocked', 'MarketBuy', 'MarketSell',
    'MiningRefined', 'CollectCargo', 'EjectCargo', 'MissionCompleted',
    'Synthesis', 'EngineerCraft', 'TechnologyBroker', 'CargoTransfer'
]


def _handle_cargo_updates(event_name: str, entry: Dict[str, Any], api_key: str, initial_timestamp: str):
    """Handles cargo updates based on events or Cargo.json."""
    global last_known_cargo

    # Cargo updates are tied to the "SendCommanderStatus" config for now
    if not this_config.get_bool(CONFIG_SEND_COMMANDER_STATUS, default=True):
        return

    inventory_to_process = []
    should_process_cargo = False
    current_timestamp = initial_timestamp

    if event_name in CARGO_TRIGGER_EVENTS:
        if event_name == 'Cargo' and 'Inventory' in entry:
            inventory_to_process = [{"Name": item.get("Name", "N/A"), "Count": item.get("Count", 0)}
                                    for item in entry['Inventory']]
            should_process_cargo = True
            current_timestamp = entry.get("timestamp", initial_timestamp)  # Prefer event timestamp
        else:
            # For other trigger events, try to read Cargo.json
            journal_dir_path_str = this_config.get_str("journaldir") or this_config.default_journal_dir
            if journal_dir_path_str:
                cargo_json_path = pathlib.Path(journal_dir_path_str) / "Cargo.json"
                try:
                    if cargo_json_path.exists():
                        with open(cargo_json_path, encoding='utf-8') as f:
                            cargo_file_data = json.load(f)
                        if 'Inventory' in cargo_file_data:
                            inventory_to_process = [{"Name": item.get("Name", "N/A"), "Count": item.get("Count", 0)}
                                                    for item in cargo_file_data['Inventory']]
                            should_process_cargo = True
                            current_timestamp = cargo_file_data.get("timestamp",
                                                                    initial_timestamp)  # Prefer Cargo.json timestamp
                except Exception as e:
                    plugin_logger.error(f"Error reading Cargo.json after event {event_name}: {e}", exc_info=True)
            else:
                plugin_logger.warning("Journal directory not configured. Cannot read Cargo.json for cargo update.")

    if should_process_cargo:
        inventory_to_process.sort(key=lambda x: x["Name"])  # Sort for consistent comparison
        if inventory_to_process != last_known_cargo:
            cargo_payload = {
                "event_type": "CargoUpdate",
                "timestamp": current_timestamp,
                "Inventory": inventory_to_process
            }
            try:
                event_queue.put((COMMANDER_STATUS_API_URL, api_key, "CommanderStatus_CargoUpdate", cargo_payload))
                plugin_logger.info(f"Queued CommanderStatus_CargoUpdate ({len(inventory_to_process)} items)")
                last_known_cargo = inventory_to_process  # Update global state
            except Exception as e:
                plugin_logger.error(f"Failed to queue CommanderStatus_CargoUpdate: {e}", exc_info=True)
        else:
            plugin_logger.info("Cargo data unchanged. Not sending update.")


def journal_entry(cmdr, is_beta, system, station, entry, state):
    global last_known_cargo, last_known_market_data
    event_name = entry.get('event')
    if not event_name: return

    timestamp = entry.get('timestamp', datetime.utcnow().isoformat() + "Z")

    if not requests or this_config is None: return

    api_key = this_config.get_str(CONFIG_API_KEY)
    if not api_key: return

    # Handle construction data (station totals)
    if event_name == 'ColonisationConstructionDepot' and this_config.get_bool(CONFIG_SEND_CONSTRUCTION_DATA,
                                                                              default=True):
        payload = entry.copy()
        if 'SystemName' in payload and 'StarSystem' not in payload:
            payload['StarSystem'] = payload.pop('SystemName')
        elif 'StarSystem' not in payload and system:
            payload['StarSystem'] = system
        if 'StationName' not in payload and station: payload['StationName'] = station

        if not payload.get('MarketID'):
            plugin_logger.warning(
                f"Skipping {event_name} for {payload.get('StationName', 'Unknown Station')} as MarketID is missing.")
            return
        try:
            # Add CMDR info to the payload for context, though backend might not use it for this specific event type's primary logic.
            payload['CMDR_reporting_FID'] = state.get('FID')
            payload['CMDR_reporting_Name'] = cmdr
            event_queue.put((CONSTRUCTION_API_URL, api_key, "ConstructionStationUpdate", payload))
            plugin_logger.info(
                f"Queued ConstructionStationUpdate for MarketID {payload.get('MarketID')} from {event_name}")
        except Exception as e:
            plugin_logger.error(f"Failed to queue ConstructionStationUpdate: {e}", exc_info=True)

    # *** NEW: Handle specific player contributions ***
    elif event_name == 'ColonisationContribution' and this_config.get_bool(CONFIG_SEND_CONSTRUCTION_DATA, default=True):
        contribution_payload = {
            "timestamp": timestamp,
            "event": event_name,  # Keep original event name
            "MarketID": entry.get('MarketID'),
            "Contributions": entry.get('Contributions', []),  # This is an array of {"Name": ..., "Amount": ...}
            # Add CMDR info to this payload as well, as it's their direct action
            "CMDR_FID": state.get('FID'),  # Get current CMDR's FID from EDMC's state
            "CMDR_Name": cmdr  # Get current CMDR's Name from EDMC
        }
        if not contribution_payload.get('MarketID') or not contribution_payload.get('Contributions'):
            plugin_logger.warning(
                f"Skipping {event_name} due to missing MarketID or Contributions array. Data: {entry}")
            return
        try:
            event_queue.put(
                (PLAYER_CONSTRUCTION_CONTRIBUTION_URL, api_key, "PlayerConstructionContribution", contribution_payload))
            plugin_logger.info(
                f"Queued PlayerConstructionContribution for MarketID {contribution_payload.get('MarketID')}. Items: {len(contribution_payload.get('Contributions', []))}")
        except Exception as e:
            plugin_logger.error(f"Failed to queue PlayerConstructionContribution: {e}", exc_info=True)

    # Handle market data from Market.json
    elif event_name == 'Market' and this_config.get_bool(CONFIG_SEND_MARKET_DATA, default=True):
        # ... (existing Market event handling logic - keep as is) ...
        market_id = entry.get('MarketID')
        if not market_id: plugin_logger.warning("Market event received, but it's missing MarketID."); return
        journal_dir_path_str = this_config.get_str("journaldir") or this_config.default_journal_dir
        if not journal_dir_path_str: plugin_logger.error(
            "Journal directory not configured. Cannot read Market.json."); return
        market_json_path = pathlib.Path(journal_dir_path_str) / "Market.json"
        try:
            if not market_json_path.exists(): plugin_logger.warning(
                f"Market.json not found: {market_json_path}"); return
            with open(market_json_path, 'r', encoding='utf-8') as f:
                market_file_data = json.load(f)
            if market_file_data.get('MarketID') != market_id:
                plugin_logger.warning(
                    f"Market.json MktID ({market_file_data.get('MarketID')}) != Event MktID ({market_id}). Stale?")
                return
            current_market_commodities = []
            if 'Items' in market_file_data:
                for item in market_file_data['Items']:
                    category_value = item.get("Category")
                    category_name = "N/A"
                    if isinstance(category_value, dict):
                        category_name = category_value.get("Name", "N/A")
                    elif isinstance(category_value, str):
                        category_name = item.get("Category_Localised", category_value)
                    current_market_commodities.append({
                        "Name": item.get("Name", "N/A"), "Name_Localised": item.get("Name_Localised"),
                        "Category": category_name, "BuyPrice": item.get("BuyPrice", 0),
                        "SellPrice": item.get("SellPrice", 0),
                        "MeanPrice": item.get("MeanPrice", 0), "StockBracket": item.get("StockBracket", 0),
                        "DemandBracket": item.get("DemandBracket", 0), "Stock": item.get("Stock", 0),
                        "Demand": item.get("Demand", 0),
                        "Consumer": item.get("Consumer", False), "Producer": item.get("Producer", False),
                        "Rare": item.get("Rare", False)
                    })
                current_market_commodities.sort(key=lambda x: x["Name"])
            if current_market_commodities != last_known_market_data.get(market_id):
                market_payload = {
                    "event_type": "MarketDataUpdate", "timestamp": market_file_data.get("timestamp", timestamp),
                    "MarketID": market_id, "StarSystem": market_file_data.get("StarSystem", system),
                    "StationName": market_file_data.get("StationName", station),
                    "StationType": market_file_data.get("StationType"),
                    "CarrierDockingAccess": market_file_data.get("CarrierDockingAccess"),
                    "Items": current_market_commodities
                }
                event_queue.put((MARKET_DATA_API_URL, api_key, "MarketDataUpdate", market_payload))
                plugin_logger.info(
                    f"Queued MarketDataUpdate for MktID {market_id} ({len(current_market_commodities)} items)")
                last_known_market_data[market_id] = current_market_commodities
            else:
                plugin_logger.info(f"Market data for MktID {market_id} unchanged. Not sending.")
        except json.JSONDecodeError as jde:
            plugin_logger.error(f"Failed to decode Market.json for MktID {market_id}: {jde}", exc_info=True)
        except Exception as e:
            plugin_logger.error(f"Failed to process Market.json for MktID {market_id}: {e}", exc_info=True)


    # Handle commander status updates (Location, LoadGame, etc.)
    elif this_config.get_bool(CONFIG_SEND_COMMANDER_STATUS, default=True):
        # ... (existing commander status event handling - keep as is for LoadGame, Location, FSDJump, Docked, Undocked etc.) ...
        # This section also handles the "CargoUpdate" which is important.
        payload = None;
        data_type_log_name = None
        base_payload = {"timestamp": timestamp, "commanderName": cmdr, "commanderFID": state.get('FID')}
        if event_name == 'LoadGame':
            data_type_log_name = "LoadGame"
            payload = {**base_payload, "event_type": "LoadGame", "credits": entry.get('Credits'),
                       "gameMode": entry.get('GameMode'),
                       "ship": entry.get('Ship'), "shipID": entry.get('ShipID'), "shipName": entry.get('ShipName'),
                       "shipIdent": entry.get('ShipIdent'), "fuelLevel": entry.get('FuelLevel'),
                       "fuelCapacity": entry.get('FuelCapacity')}
        elif event_name == 'Location':
            data_type_log_name = "LocationUpdate"
            payload = {**base_payload, "event_type": "LocationUpdate", "systemName": entry.get('StarSystem'),
                       "starPos": entry.get('StarPos'),
                       "body": entry.get('Body'), "bodyType": entry.get('BodyType'),
                       "docked": entry.get('Docked', False),
                       "stationName": entry.get('StationName') if entry.get('Docked') else None,
                       "stationType": entry.get('StationType') if entry.get('Docked') else None,
                       "marketID": entry.get('MarketID') if entry.get('Docked') else None,
                       "onFoot": entry.get('OnFoot', False)}
        elif event_name == 'FSDJump':
            data_type_log_name = "FSDJump"
            payload = {**base_payload, "event_type": "FSDJump", "StarSystem": entry.get('StarSystem'),
                       "starPos": entry.get('StarPos'),
                       "jumpDist": entry.get('JumpDist'), "fuelUsed": entry.get('FuelUsed'),
                       "fuelLevel": entry.get('FuelLevel')}
        elif event_name == 'Docked':
            data_type_log_name = "Docked"
            payload = {**base_payload, "event_type": "Docked", "StarSystem": entry.get('StarSystem'),
                       "StationName": entry.get('StationName'), "StationType": entry.get('StationType'),
                       "MarketID": entry.get('MarketID')}
        elif event_name == 'Undocked':
            data_type_log_name = "Undocked"
            payload = {**base_payload, "event_type": "Undocked", "StationName": entry.get('StationName')}
        # ... (other status events like CarrierJump, Statistics, Embark, Disembark, Shutdown) ...
        elif event_name == 'CarrierJump':
            data_type_log_name = "CarrierJump"
            payload = {**base_payload, "event_type": "CarrierJump", "StarSystem": entry.get('StarSystem'),
                       "Body": entry.get('Body'),
                       "BodyID": entry.get('BodyID'), "SystemAddress": entry.get('SystemAddress'),
                       "Docked": entry.get('Docked', False),
                       "StationName": entry.get('StationName'), "MarketID": entry.get('MarketID')}
        elif event_name == 'Statistics':
            data_type_log_name = "StatisticsUpdate"
            payload = {**base_payload, "event_type": "StatisticsUpdate",
                       "Bank_Account": {"Current_Wealth": entry.get('Bank_Account', {}).get('Current_Wealth')}}
        elif event_name == 'Embark' or event_name == 'Disembark':
            data_type_log_name = event_name
            payload = {**base_payload, "event_type": event_name, "SRV": entry.get('SRV', False),
                       "Taxi": entry.get('Taxi', False),
                       "Multicrew": entry.get('Multicrew', False), "OnStation": entry.get('OnStation', False),
                       "OnPlanet": entry.get('OnPlanet', False), "StationName": entry.get('StationName'),
                       "StationType": entry.get('StationType'), "Body": entry.get('Body'),
                       "BodyID": entry.get('BodyID'), "ID": entry.get('ID')}
        elif event_name == 'Shutdown':
            data_type_log_name = "Shutdown"
            payload = {**base_payload, "event_type": "Shutdown"}

        if payload and data_type_log_name:
            try:
                event_queue.put((COMMANDER_STATUS_API_URL, api_key, f"CommanderStatus_{data_type_log_name}", payload))
                plugin_logger.info(f"Queued CommanderStatus_{data_type_log_name}")
            except Exception as e:
                plugin_logger.error(f"Failed to queue CommanderStatus_{data_type_log_name}: {e}", exc_info=True)

        # Cargo update logic (important for snapshotting)
        inventory_to_process = [];
        send_cargo_update = False
        cargo_trigger_events = ['Cargo', 'LoadGame', 'Docked', 'Undocked', 'MarketBuy', 'MarketSell',
                                'MiningRefined', 'CollectCargo', 'EjectCargo', 'MissionCompleted',
                                'Synthesis', 'EngineerCraft', 'TechnologyBroker', 'CargoTransfer']

        if event_name in cargo_trigger_events:
            if event_name == 'Cargo' and 'Inventory' in entry:
                inventory_to_process = [{"Name": item.get("Name", "N/A"), "Count": item.get("Count", 0)} for item in
                                        entry['Inventory']]
                send_cargo_update = True
                timestamp = entry.get("timestamp", timestamp)
            else:
                journal_dir_path_str = this_config.get_str("journaldir") or this_config.default_journal_dir
                if journal_dir_path_str:
                    cargo_json_path = pathlib.Path(journal_dir_path_str) / "Cargo.json"
                    try:
                        if cargo_json_path.exists():
                            with open(cargo_json_path, 'r', encoding='utf-8') as f:
                                cargo_file_data = json.load(f)
                            if 'Inventory' in cargo_file_data:
                                inventory_to_process = [{"Name": item.get("Name", "N/A"), "Count": item.get("Count", 0)}
                                                        for item in cargo_file_data['Inventory']]
                                send_cargo_update = True;
                                timestamp = cargo_file_data.get("timestamp", timestamp)
                    except Exception as e:
                        plugin_logger.error(f"Error reading Cargo.json after event {event_name}: {e}", exc_info=True)

        if send_cargo_update:
            inventory_to_process.sort(key=lambda x: x["Name"])
            if inventory_to_process != last_known_cargo:
                # *** This is the payload that updates CommanderProfile.cargo_manifest_json ***
                cargo_payload = {
                    "event_type": "CargoUpdate",  # Specific event type for this
                    "timestamp": timestamp,
                    "Inventory": inventory_to_process,
                    "CMDR_FID": state.get('FID'),  # Add FID
                    "CMDR_Name": cmdr  # Add Name
                }
                try:
                    event_queue.put((COMMANDER_STATUS_API_URL, api_key, "CommanderStatus_CargoUpdate", cargo_payload))
                    plugin_logger.info(f"Queued CommanderStatus_CargoUpdate ({len(inventory_to_process)} items)")
                    last_known_cargo = inventory_to_process
                except Exception as e:
                    plugin_logger.error(f"Failed to queue CommanderStatus_CargoUpdate: {e}", exc_info=True)
            else:
                plugin_logger.info("Cargo data unchanged. Not sending update.")
