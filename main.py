import logging
from nss_home import *

logger = logging.getLogger('nss_home')
logger.setLevel(logging.ERROR)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


def main():
    gw = Gateway("")
    devices = gw.get_devices_list()
    devices.append(gw.gateway_info.sid)
    for device_id in devices:
        print(gw.get_device_status(device_id))
    gw.set_events_handler(lambda data: print(data))


if __name__ == "__main__":
    main()
