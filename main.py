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


def main():
    influx_client = InfluxDBClient(
        INFLUXDB_HOST, INFLUXDB_PORT, INFLUXDB_USER, INFLUXDB_PASSWORD, INFLUXDB_DB
    )
    if INFLUXDB_DB not in [db["name"] for db in influx_client.get_list_database()]:
        influx_client.create_database(INFLUXDB_DB)

    gw = Gateway(GATEWAY_PASSWORD)

    devices = gw.get_devices_list()
    devices.append(gw.gateway_info.sid)
    for device_id in devices:
        print(gw.get_device_status(device_id))

    gw.set_events_handler(gateway_events_handler)


def gateway_events_handler(data):
    print(data)


if __name__ == "__main__":
    main()
