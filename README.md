# rpi-dbt03
Hardware, Software and Firmware for a Raspberry Pi to DBT-03 adapter


There is now a possibility to directly patch a Bookworm Raspbian image.

Run `./patch_image.sh <imagename>` as root. It only works on uncompressed images. You can then `dd` that image onto your SD-card or use the Raspberry Pi Imager. The later also allows you to set settings.
The image will reboot multiple times.

The boot partition can also hold a `btx_config.txt` file where you can configure the host to connect to.

```
BTX_HOST=btx.clarke-3.de
BTX_PORT=20000
BTX_PROTO=raw
```

`BTX_PROTO` selects the wire protocol spoken with the terminal: `raw`
(default, transparent octet passthrough), `raw7` (same, but with a 7-bit +
even-parity transform on every octet), or `layer2` (the host terminates the
Bildschirmtext layer-2 exchange itself instead of passing octets through
blindly). See `protocols.txt` for details.

## Old way of installing it

On the Raspberry PI check out this repository. 

Install the packages in install-packages.sh (run it as root). 

Enable spi with raspi-config. 

Change the baudrate of the programmer "linuxspi" to a smaller value 40000 is OK. This setting is found in /etc/avrdude.conf



This currently is still incomplete.
