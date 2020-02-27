#!/usr/bin/env bash
JLinkGDBServerCLExe -if swd -device S32K144 -endian little -speed 1000 -port 2331 -swoport 2332 -telnetport 2333 -vd -ir -localhostonly 1 -strict -timeout 0 -nogui -vd
