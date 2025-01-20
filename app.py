#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# MIT License

# Copyright (c) 2021 Matt Doyle

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import datetime
import functools
import http.client
import json
import nmap
import os
import requests
import signal
import sys
import time
import urllib

from pushoverutil import Push
from scapy.all import arping
from threading import Thread, RLock


@functools.cache
def LoadConfigJson():

    config_path = "/config.json"
    if not os.path.isfile(config_path):
        print("config.json not found")
        sys.exit(1)

    with open(config_path) as f:
        return json.load(f)


@functools.lru_cache
def GetMacVendor(mac):
    # Lazy way to meet the macvendors.com rate limiting of 1 QPS.
    time.sleep(1)

    response = requests.get(f"http://api.macvendors.com/{mac}")
    return response.text if response.status_code == http.client.OK else "????"


def Now():
    return datetime.datetime.now()


def TimeSince(dt):
    delta = Now() - dt

    s = int(delta.total_seconds() % 60)
    m = int((delta.total_seconds() % 3600) / 60)
    h = int(delta.total_seconds() / 3600)

    return " ".join(
        filter(
            None,
            [
                f"{h}h" if h else None,
                f"{m}m" if m else None,
                f"{s}s" if (s or (not h and not m)) else None,
            ],
        )
    )


def IsOlderThan(dt, **kwargs):
    return Now() - dt > datetime.timedelta(**kwargs)


class BaseThread(Thread):

    def __init__(self):
        super().__init__()

        self.running = False
        self.lock = RLock()

        config_json = LoadConfigJson()

        # Load Pushover credentials, if they're present.
        self.pushover_app_token = config_json.get("pushover_app_token")
        self.pushover_user_key = config_json.get("pushover_user_key")
        self.pushover_enabled = bool(self.pushover_app_token and self.pushover_user_key)

        # Load the subnet(s), which are required.
        self.subnets = config_json.get("subnets", [])
        if not self.subnets:
            print("ERROR: No subnet(s) specified to scan")
            sys.exit(1)

        # Load the various device lists.
        self.permanent_devices = {
            item["mac"]: item["name"]
            for item in config_json.get("permanent_devices", {})
        }
        self.transient_devices = {
            item["mac"]: item["name"]
            for item in config_json.get("transient_devices", {})
        }
        self.interloper_devices = {
            item["mac"]: item["name"]
            for item in config_json.get("interloper_devices", {})
        }
        self.all_devices = (
            self.permanent_devices | self.transient_devices | self.interloper_devices
        )

    def Start(self):
        with self.lock:
            self.running = True
            self.start()

    def Stop(self):
        with self.lock:
            self.running = False

    def IsRunning(self):
        with self.lock:
            return self.running

    def Pushover(self, message):
        print(message)
        if self.pushover_enabled:
            Push(self.pushover_user_key, self.pushover_app_token, message)

    def run(self):
        try:
            self.InnerRun()
        except Exception as e:
            self.Pushover(f"{e.__class__.__name__}: {str(e)}")


class ArpThread(BaseThread):

    def RunArpScans(self):

        all_results = []
        for subnet in self.subnets:

            arping_results, _ = arping(subnet, timeout=20, verbose=0)

            # Compose the answers into a list of tuples, mapping MACs to IPs,
            # sorted by IP.
            results = [
                (item.answer.hwsrc.upper(), item.answer.psrc)
                for item in sorted(list(arping_results), key=lambda i: i.answer.psrc)
            ]

            print(f"Scan of {subnet} found {len(results)} device(s)")
            for mac, ip in results:
                device_name = self.all_devices.get(mac, "????")
                ip_str = f"{ip}:"
                print(f"  {ip_str : <16} {device_name}")

            all_results += results

        return all_results

    def InnerRun(self):
        print("Starting network scanning thread")

        # Keep track of the devices that were seen by the last scan.
        previous_devices = {}

        # Keep track of the "last seen" and "last alert" times of certain
        # devices.
        last_seen_times = {}
        last_alert_times = {}

        while self.IsRunning():

            # Send ARP requests out to the subnet to see which devices are
            # present.
            current_devices = self.RunArpScans()

            # Loop through all of the found devices.
            for mac, ip in current_devices:

                last_seen_time = last_seen_times.get(mac)
                last_seen_times[mac] = Now()

                # Skip all transient devices.
                if mac in self.transient_devices:
                    continue

                # Only alert about permanent devices coming back online if
                # there's a last seen time, and the device has been missing
                # sufficiently long.
                elif mac in self.permanent_devices:

                    # First appearance after a restart won't have a last seen
                    # time, so don't bother alerting.
                    if not last_seen_time:
                        continue

                    # If the device is back online after a long absence, alert.
                    elif IsOlderThan(last_seen_time, minutes=10):
                        name = self.permanent_devices[mac]
                        time_since = TimeSince(last_seen_time)
                        self.Pushover(f"{name} is back online after {time_since}")

                # If an interloper device has appeared since the last scan, then
                # notify, but only if it's been > 6h since it was last seen.
                elif mac in self.interloper_devices:
                    if not last_seen_time or IsOlderThan(last_seen_time, hours=6):
                        name = self.interloper_devices[mac]
                        self.Pushover(f"{name} has connected as {ip}")

                # Device is unknown, so periodically scan and alert.
                else:
                    last_alert_time = last_alert_times.get(mac)
                    if not last_alert_time or IsOlderThan(last_alert_time, minutes=30):
                        last_alert_times[mac] = Now()
                        vendor = GetMacVendor(mac)
                        self.Pushover(
                            f"Unknown '{vendor}' device connected (MAC: {mac}, IP: {ip})"
                        )

                        # Kick off a scan of the unknown device.
                        NmapThread(ip).Start()

            # Alert if any permanent devices have been offline for too long.
            for mac, name in self.permanent_devices.items():

                last_seen_time = last_seen_times.get(mac)
                last_alert_time = last_alert_times.get(mac)
                recently_went_offline = last_seen_time and IsOlderThan(
                    last_seen_time, minutes=10
                )
                have_not_recently_alerted = (
                    not last_alert_time or last_alert_time < last_seen_time
                )

                if recently_went_offline and have_not_recently_alerted:
                    last_alert_times[mac] = Now()
                    self.Pushover(f"{name} has gone offline")

            previous_devices = current_devices


class NmapThread(BaseThread):

    def __init__(self, ip_address):
        super().__init__()

        self.ip_address = ip_address

    def InnerRun(self):
        scanner = nmap.PortScanner()
        scanner.scan(self.ip_address, arguments="-O")
        results = (
            scanner[self.ip_address] if scanner.has_host(self.ip_address) else None
        )

        if results:
            hostnames = results.get("hostnames")
            hostname = hostnames[0].get("name", "????") if hostnames else "????"
            osmatches = results.get("osmatch")
            osmatch = osmatches[0].get("name", "????") if osmatches else "????"
        else:
            hostname = "????"
            osmatch = "????"

        self.Pushover(
            f"Device at {self.ip_address} scanned. Hostname: {hostname}, OS: {osmatch}"
        )


def ExitHandler(base_thread, unused_signo, unused_stack_frame):
    base_thread.Stop()


def main():
    arp_thread = ArpThread()

    # Set up exit handling for the ARP thread. See documentation:
    # https://docs.python.org/3/library/signal.html#signal.signal
    exit_handler = functools.partial(ExitHandler, arp_thread)
    signal.signal(signal.SIGTERM, exit_handler)
    signal.signal(signal.SIGINT, exit_handler)

    # Start the ARP thread.
    arp_thread.Start()
    arp_thread.join()


if __name__ == "__main__":
    main()
