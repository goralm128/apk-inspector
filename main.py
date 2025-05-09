import json
from utils.apk_utils import install_apks
from utils.frida_utils import trace_open_files

APK_FOLDER = "apks"
FRIDA_SCRIPT = "frida_hooks/hook_open.js"
OUTPUT_JSON = "output/results.json"

def main():
    results = {}

    print(" Installing APKs...")
    package_names = install_apks(APK_FOLDER)

    for package in package_names:
        print(f" Tracing file access for: {package}")
        try:
            paths = trace_open_files(package, FRIDA_SCRIPT)
            results[package] = paths
        except Exception as e:
            print(f" Error tracing {package}: {e}")
            results[package] = []

    print(f" Writing results to {OUTPUT_JSON}")
    with open(OUTPUT_JSON, "w") as f:
        json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
