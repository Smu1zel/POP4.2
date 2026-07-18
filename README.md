# POP4.2
This is an experimental patcher that allows CPUs *with* POPCNT, but *without* SSE4.2 (such as the AMD Phenom and K10 lines of CPUs) to boot Windows 11 24H2 and beyond. It has been tested on Windows 11 25H2 v2. Other builds have not been tested, but should work.

## What? Windows 11 needs that. This is impossible!
Yes and no. while Windows 11 checks for *both* POPCNT and SSE4.2, it does not actually need SSE4.2 for 99% of its files, with only a singular exception that can be worked around (read on). To enforce this, Microsoft uses the undocumented ``RtlDetectProcessorFeatures`` function and checks for a few requirements by reading data from .rdata. In kernel 26100.7171, this is at offset ``00000001400088C0`` and has the bytes ``01 00 00 00 00 00 00 00 00 00 10 00 02 00 00 00 0D 00 00 00`` in IDA. To defeat this, we simply flip that ``0D`` to a ``0C``, telling Windows to effectively skip the check and continue booting.

## Okay, so how do I use this?
First, extract ntoskrnl from boot.wim from the Windows 11 build you'd like to patch. Run my patcher, keep the default options (unless you're me or know what you're doing!), and patch the file. After that, obtain a copy of WindowsCodecs.dll from 23H2 (see "Why WindowsCodecs.dll?" for more info) and place it in the same directory. After that, run ``Set-ExecutionPolicy Unrestricted`` in an elevated PowerShell prompt, mount the ISO in Windows, and use the following syntax:
``.\build_patched_iso.ps1 -IsoDrive "\<drive letter\>:" -Index \<install.wim/esd index number\> -OscdimgPath "\<path to oscdimg.exe\>"``. After running it, you will get an ISO you can then use in VMs, Rufus/Ruflux, or other online utilities. It is recommended that, if you are using Rufus/Ruflux, that you apply its system requirements patches. While I handle the hard machine code checks, I do not patch what setup.exe wants. Ensure you press F8 at boot to disable driver signature enforcement.

## Why WindowsCodecs.dll?
For some reason, Microsoft compiled this specific DLL with SSE4.1 instructions. If you do not replace this, it will attempt to execute instruction ``PMOVSXBW`` (bytes ``, crash, and since setup.exe utilizes it, Windows Setup will crash and restart. Even if you deploy the WIM manually, Windows will later enter Automatic Recovery since it tries to execute setup.exe again to finish installing. For these reasons, replacing this is required.

## Known issues
- Certain Nvidia nForce chipsets hang on boot. Needs further investigation.
- You must manually enable the legacy boot menu and press F8 to disable driver signature enforcement.
- This whole thing is experimental. Please file any bugs or quirks you find in the Issues tab. I don't even have Phenom hardware; I used QEMU.

## Screenshot

![Screenshot](Screenshot.png)

## Credits
- Bob Pony, for letting me test on his machine.
- QEMU, for making a great emulator and debugger.
- Google, for making Gemini, a great model that helped me figure this out.
- IDA, for their invaluable disassembler.
- Microsoft, for Windows 11.

## License
This program, its accompanying files, and all files otherwise included in this repository are licensed under the MIT License. Consult the LICENSE file for details.