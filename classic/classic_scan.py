"""List Bluetooth Classic and LE devices Windows can see (paired and unpaired)."""
import asyncio
from winrt.windows.devices.bluetooth import BluetoothDevice, BluetoothLEDevice
from winrt.windows.devices.enumeration import DeviceInformation


async def main():
    for label, cls in (("CLASSIC", BluetoothDevice), ("LE", BluetoothLEDevice)):
        for paired in (True, False):
            sel = cls.get_device_selector_from_pairing_state(paired)
            try:
                found = await DeviceInformation.find_all_async_aqs_filter(sel)
            except Exception as e:
                print(f"{label} paired={paired}: error {e}")
                continue
            print(f"== {label} paired={paired}: {found.size}")
            for d in found:
                print(f"   {d.name!r}  {d.id[-17:]}")


asyncio.run(main())
