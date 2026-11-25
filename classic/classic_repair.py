"""Unpair (if paired) then pair a classic Bluetooth device supplying a PIN."""
import asyncio
import sys
from winrt.windows.devices.bluetooth import BluetoothDevice
from winrt.windows.devices.enumeration import DevicePairingKinds, DevicePairingProtectionLevel


async def main(mac: str, pin: str):
    addr = int(mac.replace(":", ""), 16)
    dev = await BluetoothDevice.from_bluetooth_address_async(addr)
    pairing = dev.device_information.pairing
    print(f"name={dev.name!r} paired={pairing.is_paired}")
    if pairing.is_paired:
        res = await pairing.unpair_async()
        print(f"unpair status={res.status!r}")
        await asyncio.sleep(3)
        dev = await BluetoothDevice.from_bluetooth_address_async(addr)
        pairing = dev.device_information.pairing
        print(f"after unpair paired={pairing.is_paired}")

    def on_request(_sender, args):
        print(f"pairing request kind={args.pairing_kind!r}")
        if args.pairing_kind == DevicePairingKinds.PROVIDE_PIN:
            args.accept(pin)
        else:
            args.accept()

    custom = pairing.custom
    token = custom.add_pairing_requested(on_request)
    try:
        res = await custom.pair_async(DevicePairingKinds.PROVIDE_PIN, DevicePairingProtectionLevel.DEFAULT)
    finally:
        custom.remove_pairing_requested(token)
    print(f"pair status={res.status!r} protection={res.protection_level_used!r}")
    dev = await BluetoothDevice.from_bluetooth_address_async(addr)
    print(f"final paired={dev.device_information.pairing.is_paired}")


asyncio.run(main(sys.argv[1], sys.argv[2]))
