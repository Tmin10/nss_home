import json
import os
import logging

from influxdb import InfluxDBClient

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


if __name__ == "__main__":
    main()
