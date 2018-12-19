#!/usr/bin/env sh
openocd -f interface/ftdi/olimex-arm-usb-tiny-h.cfg -f target/lpc4357.cfg
