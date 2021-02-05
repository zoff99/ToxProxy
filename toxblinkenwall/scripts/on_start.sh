#! /bin/bash

# turn green led to blink
echo 'heartbeat' | sudo tee --append /sys/class/leds/led0/trigger >/dev/null 2>/dev/null

echo "-starting-" > /home/pi/ToxBlinkenwall/toxblinkenwall/share/online_status.txt 2>/dev/null

