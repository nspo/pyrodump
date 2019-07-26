# pyrodump

pyrodump is a simple graphical interface for airodump-ng. It currently can be used to monitor networks and deauthenticate clients from your network.

## Bugs
Pyrodump was only tested on a single computer with Ubuntu 18.04 so far. Some commands may not work on different systems - please create issues on Github in that case.

## Disclaimer
You are responsible for correct and lawful usage of this tool yourself. Don't do anything you don't understand.

## Usage

Install airodump-ng first. Then:

```bash
chmod +x pyrodump.py
sudo ./pyrodump.py
```

Select your WiFi interface if it's not selected by default. Activate monitor mode with M`Monitor mode -> Start`.

Start Airodump with `Airodump -> Start`.

If a client needs to be deauthenticated, stop airodump, select the client and then select `Client -> Start deauth`. 
