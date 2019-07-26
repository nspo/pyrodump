#!/usr/bin/env python3
import os
import shlex
import subprocess
import sys
import re
import csv
from collections import OrderedDict


def get_wifi_interfaces():
    interfaces = os.listdir('/sys/class/net/')
    wifi_interfaces = []
    for iface in interfaces:
        if os.path.exists('/sys/class/net/{}/wireless'.format(iface)):
            wifi_interfaces.append(iface)

    return wifi_interfaces


def get_wifi_interface_type(iface):
    proc = subprocess.Popen(["iw", "dev", iface, "info"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    stdout, _ = proc.communicate()
    stdout = stdout.decode("utf-8")

    errcode = proc.returncode

    if errcode != 0:
        return None

    expr = re.compile("type ([a-z]*)")

    match = expr.search(stdout)
    if not match:
        return None

    iface_type = match.group(1)

    return iface_type


class AccessPointRow:
    def __init__(self, row):
        self.bssid = row[0].strip()
        self.first_time_seen = row[1].strip()
        self.last_time_seen = row[2].strip()
        self.channel = row[3].strip()
        self.speed = row[4].strip()
        self.privacy = row[5].strip()
        self.cipher = row[6].strip()
        self.authentication = row[7].strip()
        self.power = row[8].strip()
        self.num_beacons = row[9].strip()
        self.num_iv = row[10].strip()
        self.lan_ip = row[11].strip()
        self.id_length = row[12].strip()
        self.essid = row[13].strip()
        self.key = row[14].strip()

    def __repr__(self):
        return str(self.__dict__)


class ClientRow:
    def __init__(self, row):
        try:
            self.mac = row[0].strip()
            self.first_time_seen = row[1].strip()
            self.last_time_seen = row[2].strip()
            self.power = row[3].strip()
            self.num_packets = row[4].strip()
            self.bssid = row[5].strip()
            self.probed_essids = row[6].strip()
        except Exception as e:
            print(e)
            print(row)

    def __repr__(self):
        return str(self.__dict__)


class AirodumpAnalyzer:
    def __init__(self, filename):
        self.filename = filename
        self.access_points = OrderedDict()
        self.running = True

    def update(self):
        if not self.running:
            return

        with open(self.filename) as f:
            reader = csv.reader(f)

            # file is actually two csv files in one -> remember if we already reached the second part
            reached_client_list = False

            for row in reader:
                if not row:
                    continue

                if row[0] == "BSSID":
                    continue  # header of first part

                if row[0] == "Station MAC":
                    reached_client_list = True
                    continue

                if not reached_client_list:
                    ap_row = AccessPointRow(row)
                    if not ap_row.bssid in self.access_points:
                        # add new entry
                        self.access_points[ap_row.bssid] = {"clients": OrderedDict()}

                    self.access_points[ap_row.bssid].update(ap_row.__dict__)  # magic
                else:
                    client_row = ClientRow(row)
                    if not client_row.bssid in self.access_points:
                        # we have not seen the AP yet -> ignore
                        continue

                    if not client_row.mac in self.access_points[client_row.bssid]["clients"]:
                        self.access_points[client_row.bssid]["clients"][client_row.mac] = {}

                    self.access_points[client_row.bssid]["clients"][client_row.mac].update(client_row.__dict__)
