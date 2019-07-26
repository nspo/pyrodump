#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import subprocess
import sys
import tempfile
import glob
import time

from PyQt5 import QtCore
from PyQt5.QtWidgets import QApplication, QLabel, QMainWindow, QVBoxLayout, QPushButton, QWidget, QGridLayout, QDialog, \
    QInputDialog, QMessageBox, QHBoxLayout, QListWidget, QFrame
from PyQt5.QtCore import QProcess, QTimer

from pyrodump_utils import *


class QErrorDialog(QMessageBox):
    def __init__(self, text, *kwargs):
        super().__init__(*kwargs)
        self.setWindowTitle("Error")
        self.setText(text)
        self.setIcon(QMessageBox.Warning)


class QHLine(QFrame):
    def __init__(self):
        super(QHLine, self).__init__()
        self.setFrameShape(QFrame.HLine)
        self.setFrameShadow(QFrame.Sunken)


class MyMainWindow(QMainWindow):

    def __init__(self):
        super(MyMainWindow, self).__init__()

        self.setWindowTitle('pyrodump')

        self.setMinimumSize(800, 640)

        self.setup_menubar()

        self.vlayout = QVBoxLayout()
        self.interface = None  # type: str
        self.btn_interface = QPushButton('No interface')
        self.btn_interface.pressed.connect(self.on_select_interface)

        self.hlayout1 = QHBoxLayout()
        self.vlayout.addLayout(self.hlayout1)
        self.hlayout1.addWidget(self.btn_interface)
        self.label_interface_type = QLabel("Type: unknown")
        self.hlayout1.addWidget(self.label_interface_type)

        self.vlayout.addWidget(QHLine())

        hlayout2 = QHBoxLayout()
        self.vlayout.addLayout(hlayout2)

        vlayout2 = QVBoxLayout()
        hlayout2.addLayout(vlayout2)
        vlayout2.addWidget(QLabel("Access Points"))
        self.ap_list = QListWidget()  # type: QListWidget
        self.ap_list.itemSelectionChanged.connect(self.ap_list_item_selection_changed)
        vlayout2.addWidget(self.ap_list)

        vlayout3 = QVBoxLayout()
        hlayout2.addLayout(vlayout3)
        vlayout3.addWidget(QLabel("Clients on selected AP"))
        self.client_list = QListWidget()
        self.client_list.itemSelectionChanged.connect(self.client_list_item_selection_changed)
        vlayout3.addWidget(self.client_list)

        self.label_ap_details = QLabel()
        self.display_ap_details()
        self.vlayout.addWidget(self.label_ap_details)

        window = QWidget()
        window.setLayout(self.vlayout)
        self.setCentralWidget(window)

        self.proc_start_monitor_mode = None  # type: QProcess
        self.proc_stop_monitor_mode = None  # type: QProcess
        self.proc_airodump = None  # type: QProcess

        self.proc_deauth = None  # type: QProcess
        self.proc_deauth_args = []  # save arguments for auto respawn
        self.proc_deauth2 = None  # type: QProcess

        self.airodump_analyzer = None  # type: AirodumpAnalyzer
        self.timer = None  # type: QTimer

        self.tempdir = tempfile.TemporaryDirectory()

        self.auto_select_interface()

    def display_ap_details(self, essid="(None)", bssid="(None}", channel="(None)", power="(None)",
                           num_beacons="(None)"):
        self.label_ap_details.setText(
            "ESSID: {}, BSSID: {}\nChannel: {}, Power: {}, # Beacons: {}".format(essid, bssid, channel, power,
                                                                                 num_beacons)
        )

    def set_interface(self, iface):
        self.interface = iface

        if iface is None:
            self.btn_interface.setText("None")
        else:
            self.btn_interface.setText(iface)
            iface_type = get_wifi_interface_type(iface)
            if iface_type:
                self.label_interface_type.setText("Type: {}".format(iface_type))
            else:
                self.label_interface_type.setText("Type: unknown")

    def auto_select_interface(self):
        ifaces = get_wifi_interfaces()

        if not ifaces:
            self.set_interface(None)
            return

        # try to find one with monitor mode enabled
        for iface in ifaces:
            if get_wifi_interface_type(iface) == "monitor":
                self.set_interface(iface)

        # fallback
        self.set_interface(ifaces[0])

    def on_select_interface(self):
        ifaces = get_wifi_interfaces()

        if not ifaces:
            QErrorDialog("No WiFi interfaces found.").exec_()
            return

        iface, ok = QInputDialog.getItem(self, "Select WiFi interface",
                                         "Select WiFi interface", ifaces, 0, False)

        self.set_interface(iface)

    def check_interface_ready(self):
        if get_wifi_interface_type(self.interface) != "monitor":
            QErrorDialog("A monitor mode interface must be started or selected first.").exec_()
            return False

        return True

    def start_airodump(self):
        print("Starting airodump...")

        if self.proc_airodump:
            self.stop_airodump()

        if not self.check_interface_ready():
            return

        cmd = "airodump-ng"
        cmd_args = [self.interface, "-w", os.path.join(self.tempdir.name, "airodump"), "--write-interval", "1", "-o",
                    "csv", "--band", "ag"]

        self.proc_airodump = QProcess()
        self.proc_airodump.start(cmd, cmd_args)
        self.monitor_mode_menu.setDisabled(True)

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_airodump_display)
        self.timer.start(1000)

    def stop_airodump(self):
        print("Stopping airodump...")

        if self.timer:
            self.timer.stop()
        if self.airodump_analyzer:
            self.airodump_analyzer.running = False
        if self.proc_airodump:
            self.proc_airodump.kill()
        self.proc_airodump = None
        self.monitor_mode_menu.setDisabled(False)

    def start_deauth_client(self):
        if self.proc_airodump or not self.client_list.selectedItems():
            QErrorDialog("How did this happen?").exec_()
            return

        if not self.check_interface_ready():
            return

        m = re.compile("^(.*) \(").search(self.client_list.selectedItems()[0].text())
        if not m:
            QErrorDialog("Could not parse client MAC").exec_()
            return

        client_mac = m.group(1)

        ap_bssid = None
        ap_channel = None
        for bssid, ap_data in self.airodump_analyzer.access_points.items():
            if client_mac in ap_data["clients"]:
                ap_bssid = bssid
                ap_channel = ap_data["channel"]
                break

        if not ap_bssid:
            QErrorDialog("Could not find AP BSSID of client with MAC {}".format(client_mac)).exec_()
            return

        print("-- Trying deauth of client with MAC {} from BSSID {}...".format(client_mac, ap_bssid))

        self.monitor_mode_menu.setDisabled(True)
        self.airodump_menu.setDisabled(True)

        # start airodump-ng on correct channel
        self.proc_deauth2 = QProcess()
        self.proc_deauth2.start("airodump-ng", [self.interface, "--band", "ag", "-c", ap_channel])

        self.proc_deauth = QProcess()
        # hack with stdbuf so that stdout/stderr is not buffered
        self.proc_deauth_args = ["-i0", "-o0", "-e0", "aireplay-ng", "--deauth=0", "-c", client_mac, "-a", ap_bssid, self.interface]
        self.proc_deauth.finished.connect(self.deauth_proc_finished)
        self.proc_deauth.readyReadStandardOutput.connect(self.deauth_proc_print_output)
        self.proc_deauth.setProcessChannelMode(QProcess.MergedChannels)
        self.proc_deauth.start("stdbuf", self.proc_deauth_args, QProcess.Unbuffered|QProcess.ReadWrite)

    def deauth_proc_print_output(self):
        if self.proc_deauth:
            print(self.proc_deauth.readAll().data().decode("utf-8"), flush=True)

    def deauth_proc_finished(self):
        if self.proc_deauth:
            print("-- aireplay-ng finished by itself -> restart")
            self.proc_deauth.start("stdbuf", self.proc_deauth_args, QProcess.Unbuffered | QProcess.ReadWrite)

    def stop_deauth_client(self):
        print("Stopping deauth...")

        self.proc_deauth2 = None
        self.proc_deauth = None

        self.monitor_mode_menu.setDisabled(False)
        self.airodump_menu.setDisabled(False)


    def update_airodump_display(self):
        if not self.airodump_analyzer or not self.airodump_analyzer.running:
            if not self.proc_airodump:
                print("! Airodump analyzer not running. Cannot update display.")
                return
            else:
                # try to create analyzer object
                match_files = self.tempdir.name + "/airodump-*.csv"
                candidate_files = glob.glob(match_files)

                if not candidate_files:
                    QErrorDialog("Could not find airodump output at location \"{}\". Stopping Airodump.".format(
                        match_files
                    )).exec_()
                    # TODO only stop on 3rd try
                    self.stop_airodump()
                    return

                file = sorted(candidate_files)[-1]  # select most recent one
                self.airodump_analyzer = AirodumpAnalyzer(file)

        self.airodump_analyzer.update()

        # remember selection - kind of ugly
        if self.ap_list.selectedItems():
            selected_item = self.ap_list.selectedItems()[0].text()
        else:
            selected_item = None

        self.ap_list.clear()

        last_channel = None
        for ap, ap_data in sorted(self.airodump_analyzer.access_points.items(), key=lambda kv: int(kv[1]["channel"])):
            if ap_data["channel"] != last_channel:
                last_channel = ap_data["channel"]
                self.ap_list.addItem("-- Channel {} --".format(last_channel))

            self.ap_list.addItem("{} (BSSID: {})".format(ap_data["essid"], ap_data["bssid"]))


        # for ap, ap_data in self.airodump_analyzer.access_points.items():
        #     self.ap_list.addItem("{} (BSSID: {})".format(ap_data["essid"], ap_data["bssid"]))

        if selected_item:
            newItemsMatching = self.ap_list.findItems(selected_item, QtCore.Qt.MatchExactly)
            if newItemsMatching:
                newItemsMatching[0].setSelected(True)
                self.ap_list.setCurrentItem(newItemsMatching[0])

    def ap_list_item_selection_changed(self):
        self.display_ap_details()

        if not self.ap_list.selectedItems():
            # unselected item
            self.client_list.clear()
            return

        selected_bssid_match = re.compile("\(BSSID: (.*)\)$").search(self.ap_list.selectedItems()[0].text())

        if not selected_bssid_match:
            self.client_list.clear()
            return

        selected_bssid = selected_bssid_match.group(1)

        if not selected_bssid in self.airodump_analyzer.access_points:
            self.client_list.clear()
            return

        ap = self.airodump_analyzer.access_points[selected_bssid]  # shorthand
        self.display_ap_details(essid=ap["essid"], bssid=ap["bssid"], channel=ap["channel"], power=ap["power"],
                                num_beacons=ap["num_beacons"])

        self.client_list.clear()
        for client_mac, client_data in ap["clients"].items():
            s = "{} (packets: {}, power: {})".format(client_data["mac"], client_data["num_packets"],
                                                     client_data["power"])
            self.client_list.addItem(s)

    def client_list_item_selection_changed(self):
        self.client_menu.setDisabled(True)

        if self.client_list.selectedItems() and not self.proc_airodump:
            self.client_menu.setDisabled(False)

    def start_monitor_mode(self):
        if self.interface is None:
            QErrorDialog("No interface selected.\nPlease select one first.").exec_()
            return

        print("Trying to start monitor mode on interface {}...".format(self.interface))

        cmd = "airmon-ng"
        cmd_args = ["start", self.interface]

        self.proc_start_monitor_mode = QProcess(self)
        self.proc_start_monitor_mode.finished.connect(self.on_start_monitor_mode_cb)
        self.proc_start_monitor_mode.start(cmd, cmd_args)
        self.menubar.setDisabled(True)

    def stop_monitor_mode(self):
        if self.interface is None:
            QErrorDialog("No interface selected.\nPlease select one first.").exec_()
            return

        print("Trying to stop monitor mode on interface {}...".format(self.interface))

        cmd = "airmon-ng"
        cmd_args = ["stop", self.interface]

        self.proc_stop_monitor_mode = QProcess(self)
        self.proc_stop_monitor_mode.finished.connect(self.on_stop_monitor_mode_cb)
        self.proc_stop_monitor_mode.start(cmd, cmd_args)
        self.menubar.setDisabled(True)

    def on_start_monitor_mode_cb(self, exitCode, exitStatus):
        self.menubar.setDisabled(False)
        stdout = self.proc_start_monitor_mode.readAllStandardOutput().data().decode("utf-8")
        self.proc_start_monitor_mode = None

        expr1 = \
            re.compile("mac80211 monitor mode [a-z]* enabled for \[phy[0-9]*\][a-z0-9]* on \[phy[0-9]*\]([a-z0-9]*)")

        match = expr1.search(stdout)
        if not match:
            QErrorDialog("Not sure if monitor mode interface was successfully created. Please select manually.").exec_()
            self.auto_select_interface()
            return

        iface = match.group(1)
        print("Enabled monitor mode for interface {}".format(iface))
        self.set_interface(iface)

    def on_stop_monitor_mode_cb(self, exitCode, exitStatus):
        self.menubar.setDisabled(False)
        stdout = self.proc_stop_monitor_mode.readAllStandardOutput().data().decode("utf-8")
        self.proc_stop_monitor_mode = None
        self.auto_select_interface()

    def setup_menubar(self):
        self.menubar = self.menuBar()

        self.monitor_mode_menu = self.menubar.addMenu("Monitor mode")
        self.monitor_mode_menu.addAction("Start").triggered.connect(self.start_monitor_mode)
        self.monitor_mode_menu.addAction("Stop").triggered.connect(self.stop_monitor_mode)

        self.airodump_menu = self.menubar.addMenu("Airodump")
        self.airodump_menu.addAction("Start").triggered.connect(self.start_airodump)
        self.airodump_menu.addAction("Stop").triggered.connect(self.stop_airodump)

        self.client_menu = self.menubar.addMenu("Client")
        self.client_menu.setDisabled(True)
        self.client_menu.addAction("Start deauth").triggered.connect(self.start_deauth_client)
        self.client_menu.addAction("Stop deauth").triggered.connect(self.stop_deauth_client)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(True)

    if os.geteuid() != 0:
        QErrorDialog("This application must be run with root privileges (use sudo).").exec_()
        sys.exit(1)

    missing_commands = []
    for cmd in ["airodump-ng", "stdbuf"]:
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            missing_commands.append(cmd)

    if missing_commands:
        QErrorDialog("The following applications must be installed on the system: {}".format(
            ", ".join(missing_commands)
        )).exec_()
        sys.exit(1)

    window = MyMainWindow()
    window.show()

    sys.exit(app.exec_())
