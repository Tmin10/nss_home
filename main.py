import json
import os
import logging
import threading
import socket

from influxdb import InfluxDBClient
from miio import AirPurifier

from nss_home import *

logger = logging.getLogger("nss_home")
logger.setLevel(logging.ERROR)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

GATEWAY_PASSWORD = os.environ["GATEWAY_PASSWORD"]
INFLUXDB_HOST = os.environ["INFLUXDB_HOST"]
INFLUXDB_PORT = os.environ.get("INFLUXDB_PORT", 8086)
INFLUXDB_USER = os.environ["INFLUXDB_USER"]
INFLUXDB_PASSWORD = os.environ["INFLUXDB_PASSWORD"]
INFLUXDB_DB = os.environ["INFLUXDB_DB"]

AIR_PURIFIER_IP = os.environ["AIR_PURIFIER_IP"]
AIR_PURIFIER_TOKEN = os.environ["AIR_PURIFIER_TOKEN"]

UPS_IP = os.environ["UPS_IP"]
UPS_PORT = os.environ.get("UPS_PORT", 3493)

INFLUXDB_CLIENT = None


def main():
    global INFLUXDB_CLIENT
    INFLUXDB_CLIENT = InfluxDBClient(
        INFLUXDB_HOST, INFLUXDB_PORT, INFLUXDB_USER, INFLUXDB_PASSWORD, INFLUXDB_DB
    )
    if INFLUXDB_DB not in [db["name"] for db in INFLUXDB_CLIENT.get_list_database()]:
        INFLUXDB_CLIENT.create_database(INFLUXDB_DB)

    gw = Gateway(GATEWAY_PASSWORD)

    devices = gw.get_devices_list()
    devices.append(gw.gateway_info.sid)
    for device_id in devices:
        print(gw.get_device_status(device_id))

    gw.set_events_handler(gateway_events_handler)

    log_air_purifier_events()
    log_ups_events()


def gateway_events_handler(data):
    if not (data["cmd"] == "heartbeat" and data["model"] == "gateway"):
        print(data)
    INFLUXDB_CLIENT.write_points(
        [
            {
                "measurement": data["cmd"],
                "tags": {
                    "model": data["model"],
                    "sid": data["sid"],
                    "short_id": int(data["short_id"]),
                },
                "fields": normalize_sensors_data(json.loads(data["data"])),
            }
        ]
    )


def normalize_sensors_data(data):
    transformations = {
        "voltage": lambda voltage: voltage / 1000,
        "humidity": lambda humidity: int(humidity) / 100,
        "temperature": lambda humidity: int(humidity) / 100,
        "no_motion": lambda no_motion: int(no_motion),
        "rgb": lambda rgb: hex(rgb)[2:],
    }
    for field in data.keys():
        if transformations.get(field):
            data[field] = transformations[field](data[field])
    return data


def log_air_purifier_events():
    threading.Timer(60.0 * 10, log_air_purifier_events).start()
    values_keys = [
        "power",
        "aqi",
        "average_aqi",
        "humidity",
        "temperature",
        "illuminance",
        "filter_life_remaining",
        "filter_hours_used",
        "motor_speed",
    ]
    air_purifier = AirPurifier(AIR_PURIFIER_IP, AIR_PURIFIER_TOKEN)
    status = air_purifier.status()
    data = {}
    for key in values_keys:
        data[key] = status.__getattribute__(key)
    data["mode"] = status.mode.value
    print(data)
    device_info = air_purifier.info()
    INFLUXDB_CLIENT.write_points(
        [
            {
                "measurement": "air_purifier",
                "tags": {
                    "model": device_info.model,
                    "firmware_version": device_info.firmware_version,
                    "hardware_version": device_info.hardware_version,
                },
                "fields": data,
            }
        ]
    )


def log_ups_events():
    threading.Timer(60.0 * 10, log_ups_events).start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((UPS_IP, UPS_PORT))
        s.settimeout(10)
        s.send(b"LIST VAR qnapups\n")
        data = ""
        while True:
            data += s.recv(4048).decode()
            if data.split("\n")[-2] == "END LIST VAR qnapups":
                break
        required_parameters = {
            "battery.charge": int,
            "battery.voltage": float,
            "device.mfr": str,
            "device.model": str,
            "input.frequency": float,
            "input.voltage": float,
            "output.voltage": float,
            "ups.load": int,
            "ups.status": str,
            "ups.temperature": float,
        }
        parameters = {}
        for line in data.split("\n"):
            if (
                not any(keyword in line for keyword in ["BEGIN", "END"])
                and "VAR" in line
            ):
                var = line.split(" ")[2:4]
                if var[0] in required_parameters:
                    parameters[var[0]] = required_parameters[var[0]](
                        var[1].replace('"', "")
                    )
        print(parameters)
        device_mfr = parameters["device.mfr"]
        device_model = parameters["device.model"]
        del parameters["device.mfr"]
        del parameters["device.model"]
        INFLUXDB_CLIENT.write_points(
            [
                {
                    "measurement": "ups",
                    "tags": {"device_mfr": device_mfr, "device_model": device_model,},
                    "fields": parameters,
                }
            ]
        )


if __name__ == "__main__":
    main()
