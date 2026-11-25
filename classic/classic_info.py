"""Read name, device class and serial-port services of a classic Bluetooth device (no pairing)."""
import asyncio
import sys
from winrt.windows.devices.bluetooth import BluetoothDevice, BluetoothCacheMode


async def main(mac: str):
    addr = int(mac.replace(":", ""), 16)
    dev = await BluetoothDevice.from_bluetooth_address_async(addr)
    if dev is None:
        print("device not reachable")
        return
    cod = dev.class_of_device
    print(f"name={dev.name!r} status={dev.connection_status!r}")
    print(f"class major={cod.major_class!r} minor={cod.minor_class!r} raw={cod.raw_value:#08x}")
    print(f"paired={dev.device_information.pairing.is_paired} can_pair={dev.device_information.pairing.can_pair}")
    try:
        res = await dev.get_rfcomm_services_async(BluetoothCacheMode.UNCACHED)
        print(f"rfcomm query error={res.error!r} count={res.services.size}")
        for s in res.services:
            print(f"   service {s.service_id.uuid} host={s.connection_host_name} name={s.connection_service_name}")
    except Exception as e:
        print(f"rfcomm query failed: {e}")


asyncio.run(main(sys.argv[1]))
