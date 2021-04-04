# pyspot_rx.py
Python script to connect to BrandMeister via Open Terminal Protocol and listen to digital amateur radio.

**Requirements**

* Valid DMR ID
* Selfcare account on BrandMeister network with enabled hotspot password
* DVMEGA DVstick 30 (ambe voice codec)
* LINUX with pulseaudio installed
* Python >= 3.?
* Various Python modules



**Usage**

* Edit pyspot_rx.cfg to your needs, then run in terminal:

```
	python3 ./pyspot_rx.py -c pyspot_rx.cfg -l /tmp/pyspot_rx.log
	
	yourID (subscibed talkgroups)>
	
	commands: add, del, help, quit
	
		a[dd] tg	subscribe to talkgroup
		d[el] tg	unsubscribe from talkgroup
		d[el]		unsubscribe from all talkgroups
		h[elp]		show help
		q[uit]		disconnect from BrandMeister and quit program
```
* View log messages in 2nd terminal:

```
	tail -f /tmp/pyspot_rx.log
```

**Hints**

* On errors install missing Python modules e.g.:

```
	python3 -m pip install pyserial
```

* Do not run pyspot_rx.py as root. Instead:
  * Grant user r/w permission to /dev/ttyUSBx. e.g.: add user to group 'dialout' or 'uucp' or '???' (depends on your distribution)
  * Or setup suitable udev rule for your DVstick30 device.


* Find the names of your pulseaudio output devices with:

```bash
	pactl list short sinks
```

**Thanks**

to BrandMeister developers and admins for support ;-)