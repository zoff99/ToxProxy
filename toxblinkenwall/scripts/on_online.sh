#! /bin/bash

# turn green led on, when online
echo 'none' | sudo tee --append /sys/class/leds/led0/trigger >/dev/null 2>/dev/null

echo "ONLINE" > /home/pi/ToxBlinkenwall/toxblinkenwall/share/online_status.txt 2>/dev/null

