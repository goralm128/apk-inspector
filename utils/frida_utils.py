import frida
import time

def trace_open_files(package_name, script_path):
    # 1. Connect to USB device
    device = frida.get_usb_device(timeout=5)

    # 2. Spawn the app (like -f in CLI)
    pid = device.spawn([package_name])
    session = device.attach(pid)

    # 3. Load the Frida script
    with open(script_path, "r") as f:
        script_code = f.read()

    script = session.create_script(script_code)

    # 4. Collect opened files
    opened_files = set()

    def on_message(message, data):
        if message["type"] == "send":
            payload = message["payload"]
            if payload.get("event") == "file_opened":
                opened_files.add(payload["path"])

    script.on("message", on_message)
    script.load()

    # 5. Resume the app (like "Resuming main thread!")
    device.resume(pid)

    # 6. Wait N seconds to collect file opens
    time.sleep(5)

    # 7. Detach and return collected paths
    session.detach()
    return list(opened_files)
