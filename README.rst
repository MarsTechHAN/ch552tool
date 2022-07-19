ch55xtool
=========

Now available on pypi
---------------------

An open sourced python command line flash tool for flashing WinChipHead
CH55x series 8051 USB micro controllers, including CH551, CH552, CH553,
CH554, CH559, CH569 (including CH56x), etc. with bootloader version(BTV)
above 2.30 (including 2.30, 2.31, 2.40, 2.71), etc.
(You can check the verision by using the official CH55x Tool.)

Usage
-----

-  **-f/–flash <filename>** Erase the whole chip, and flash the bin file
   to the CH55x.
-  **-e/–erase_flash** Erase the whole program flash.
-  **–verify_flash** [filename] Verify program flash contend with given
   file, if filename ommited verifying with flashed data. No verifying
   perormed without this flag.
-  **-r/–reset_at_end** Issue reset and run after all.
-  **-d/–data <filename>** Erase the whole data flash and write the bin
   file to the CH55x.
-  **-c/–erase_dataflash** Erase the whole data flash.
-  **–verify_data** [filename] Verify data flash contend with given
   file, if filename ommited verifying with written data. No verifying
   perormed without this flag.
-  **-g/–read_dataflash** Read content of data flash to file.
-  **-p/–print_chip_cfg** Read and print chip configuration bits 3 x 32
   bit values.

.. code:: bash

   python3 -m ch55xtool -f THE_BINARY_FILE.bin

Tool Setup
----------

-  Linux Distros > Most Linux distros come with libusb, so you only need
   to install the pyusb packge.

.. code:: bash

   python3 -mpip install ch55xtool

-  Mac OS

..

   For Mac OS, you need to install both libusb and pyusb.

.. code:: bash

   # If you dont have brew installed.
   # /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
   brew install libusb
   python3 -mpip install ch55xtool

-  As for Windows, oh no… :(

      1. First, you need to download the
         `Zadig <https://zadig.akeo.ie/>`__ for replacing the CH375
         driver from WCH to libusb.
      2. Click the Options->List all devices, to show all devices
      3. Find the device marked with **USB Module**, which presented
         driver is **CH375_balabala**
      4. Replace the driver with libusb-win32.
      5. Install the pyusb package with ``python -mpip install pyusb``.
         Since for windows, they dont use python3, but you have to make
         sure you have the pythono3 in the PATH
      6. If you want to use the WCH Toolchain, open the device manager,
         find the device marked with **libusb-win32 deives**, right
         clicked on it, and Uninstall the driver and delete the driver.
         You can also check the FAQ of Zadig
         `HERE <https://github.com/pbatard/libwdi/wiki/Zadig>`__.

FAQ
---

-  Why I got a **Error: No backend available** ?

..

   On windows, this means you dont a valid libusb device, see the guide
   above. For other system, you might dont have the libusb installed,
   follow the guide above.

-  Why it said **NO_DEV_FOUND** ?

..

   Pyusb unable to fine the device with given PID&VID. Maybe you dont
   power on your device, or it is not in DFU mode.

-  I got a **USB_ERROR_CANNOT_SET_CONFIG** error.

..

   This high probability is a permission issue. Add
   ``SUBSYSTEM=="usb", ATTRS{idVendor}=="4348", MODE="0666"`` to
   ``/etc/udev/rules.d/50-ch55x.rules``, and re-plug your device.
   Otherwise you need sudo.

-  I got a **USB_ERROR_CANNOT_DETACH_KERNEL_DRIVER**, or
   **USB_ERROR_CANNOT_CLAIM_INTERFACE** error.

..

   I never met with those problems on a working CH552. Checking the
   power, the previliage, and praying may help.

-  What if it return **Bootloader version not supported**?

..

   The program dont support BTVER lower than 2.30(welcome PR, but since
   they are too old, I dont have plan to support them). Or maybe they
   have a newer verison, for this situlation, it is welcome for you to
   open an issue.
