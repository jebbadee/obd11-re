"""Drop the classic pairing, then look for the dongle's LE side (scan + direct LE connect by address).

Usage: python le_after_unpair.py <MAC>      (re-pair later with classic_repair.py <MAC> 1234)
"""
import asyncio
import sys
from bleak import BleakScanner
from winrt.windows.devices.bluetooth import BluetoothDevice, BluetoothLEDevice


async def main(mac: str):
    addr = int(mac.replace(":", ""), 16)
    dev = await BluetoothDevice.from_bluetooth_address_async(addr)
    if dev and dev.device_information.pairing.is_paired:
        res = await dev.device_information.pairing.unpair_async()
        print(f"classic unpair: {res.status!r}")
        dev.close()
        await asyncio.sleep(6)

    found = await BleakScanner.discover(timeout=12, return_adv=True)
    rows = sorted(found.values(), key=lambda x: -x[1].rssi)
    print(f"LE devices seen: {len(rows)}; strongest 8:")
    for d, adv in rows[:8]:
        print(f"   {d.address} rssi={adv.rssi} name={adv.local_name!r} uuids={adv.service_uuids} "
              f"mfr={ {k: v.hex() for k, v in adv.manufacturer_data.items()} }")
    hit = [d for d, _ in rows if d.address.upper() == mac.upper()]
    print(f"same address advertising over LE: {bool(hit)}")

    le = await BluetoothLEDevice.from_bluetooth_address_async(addr)
    if le is None:
        print("direct LE lookup by address: not found")
        return
    print(f"direct LE lookup: name={le.name!r} status={le.connection_status!r}")
    res = await le.get_gatt_services_async()
    print(f"gatt status={res.status!r} services={[str(s.uuid) for s in res.services]}")


asyncio.run(main(sys.argv[1]))
