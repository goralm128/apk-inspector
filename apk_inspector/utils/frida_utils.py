import time
import frida


def trace_frida_events(package_name, script_path, timeout=10):
    events = []
    pid = None
    session = None

    try:
        device = frida.get_usb_device(timeout=5)
        pid = device.spawn([package_name])
        session = device.attach(pid)

        with open(script_path, "r", encoding="utf-8") as f:
            script = session.create_script(f.read())

        def on_message(message, data):
            if message["type"] == "send":
                payload = message["payload"]
                if isinstance(payload, dict):
                    events.append(payload)
            elif message["type"] == "error":
                print(f"[FRIDA ERROR] {message.get('stack', message)}")

        script.on("message", on_message)
        script.load()
        device.resume(pid)

        time.sleep(timeout)

    except Exception as e:
        print(f"[FRIDA ERROR] Tracing failed for {package_name}: {e}")
    finally:
        try:
            if session:
                session.detach()
            if pid:
                device.kill(pid)
        except Exception as cleanup_err:
            print(f"[FRIDA WARNING] Cleanup failed for {package_name}: {cleanup_err}")

    return events
