ch55x-tool
------------

An open sourced python command line flash tool for flashing WinChipHead CH55x series 8051 USB micro controllers, including CH551, CH552, CH553, CH554, and CH559  with bootloader version 2.30 or 2.31.

Usage
------------
* __-f \<filename\>__ Erase the whole chip, and flash the bin file to the CH55x.
* __-r__ Issue reset and run after the flashing.
* __-d__ Debug mode, if enabled, will print out all USB communications.

Tool Setup
------------
* Linux Distros
  > Most Linux distros come with libusb, so you only need to install the pyusb packge.
```bash
python3 -mpip install pyusb
```

* Mac OS
 > For Mac OS, you need to install both libusb and pyusb.

```bash
# If you dont have brew installed.
# /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
brew install libusb
python3 -mpip install pyusb
```

* As for Windows, oh no... :(
  > 1. First, you need to download the [Zadig](https://zadig.akeo.ie/) for replacing the CH375 driver from WCH to libusb.
  > 2. Click the Options->List all devices, to show all devices
  > 3. Find the device marked with __USB Module__, which presented driver is __CH375_balabala__
  > 4. Replace the driver with libusb-win32.
  > 5. Install the pyusb package.
 ```
 python -mpip install pyusb #Since for windows, they dont use python3, but you have to make sure you have the pythono3 in the PATH
 ```
  > 6. If you want to use the WCH Toolchain, open the device manager, find the device marked with __libusb-win32 deives__, right clicked on it, and Uninstall the driver and delete the driver. You can also check the FAQ of Zadig [HERE](https://github.com/pbatard/libwdi/wiki/Zadig).
  
 FAQ
 ---------
 * Why I got a __Error: No backend available__ ?
 > On windows, this means you dont a valid libusb device, see the guide above. For other system, you might dont have the libusb installed, follow the guide above.
 
 * Why it said __NO_DEV_FOUND__ ?
 > Pyusb unable to fine the device with given PID&VID. Maybe you dont power on your device, or it is not in DFU mode.
 
 * I got a __USB_ERROR_CANNOT_SET_CONFIG__ error.
 > This high probability is a permission issue. Add ``SUBSYSTEM=="usb", ATTRS{idVendor}=="4348", MODE="0666"`` to ``/etc/udev/rules.d/50-ch55x.rules``, and re-plug your device. Otherwise you need sudo.
 
 * I got a __USB_ERROR_CANNOT_DETACH_KERNEL_DRIVER__, or __USB_ERROR_CANNOT_CLAIM_INTERFACE__ error.
 > I never met with those problems on a working CH552. Checking the power, the previliage, and praying may help.
 
 * What if it return __Bootloader version not supported__?
 > The program dont support BTVER lower than 2.30(welcome PR, but since they are too old, I dont have plan to support them). Or maybe they have a newer verison, for this situlation, it is welcome for you to open an issue.
