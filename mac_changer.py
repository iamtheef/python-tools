#!/usr/bin/env python

import subprocess
import optparse
import re


def change_mac(interface, new_mac):
    print("[+] Changing MAC address to " + new_mac + " for " + interface)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Target Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")
    (options, args) = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify a target interface")
    elif not options.new_mac:
        parser.error("[-] Please specify a new MAC address")
    return options


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface], encoding='utf8')
    mac_search = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_search:
        return mac_search.group(0)
    else:
        return None


def check_if_changed(current_mac, new_mac):
    if current_mac == new_mac:
        print("[+] MAC address changed successfully to " + current_mac)
    else:
        print("[-] MAC address failed to change")


opts = get_arguments()
change_mac(opts.interface, opts.new_mac)
check_if_changed(get_current_mac(opts.interface), opts.new_mac)



