import frida
import time
from pathlib import Path

def trace_frida_events(package_name, frida_script_path, timeout=10):
    events = []
    pid = None  # Ensure pid exists for finally block

    def on_message(message, data):
        if message["type"] == "send":
            events.append(message["payload"])
        elif message["type"] == "error":
            print(f"Frida error: {message['stack']}")

    try:
        print(f"Launching and hooking into: {package_name}")
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        session = device.attach(pid)

        script_source = Path(frida_script_path).read_text()
        script = session.create_script(script_source)
        script.on("message", on_message)

        print("Loading Frida script...")
        script.load()

        device.resume(pid)  # Resume after hook is loaded
        print(f"Collecting events for {timeout} second(s)...")
        time.sleep(timeout)

        session.detach()
        return events

    except frida.ProcessNotFoundError:
        print(f" Failed to start or attach to: {package_name}")
        return []

    except frida.InvalidOperationError:
        print(f" Invalid operation for: {package_name}")
        return []

    except Exception as e:
        print(f" An unexpected error occurred: {e}")
        return []

    finally:
        if pid is not None:
            try:
                device.kill(pid)
            except Exception as e:
                print(f" Failed to kill process {pid}: {e}")
