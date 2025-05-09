from pathlib import Path
import subprocess

def uninstall_package(package_name):
    print(f" Uninstalling existing package: {package_name}")
    result = subprocess.run(["adb", "uninstall", package_name], capture_output=True, text=True)
    if "Success" in result.stdout:
        print(f" Uninstalled: {package_name}")
    else:
        print(f" Uninstall response: {result.stdout.strip()}")

def install_apks(folder_path):
    apk_folder = Path(folder_path)
    apk_files = list(apk_folder.rglob("*.apk"))
    package_names = []

    for apk in apk_files:
        pkg_name = apk.stem.split("_")[0]  # Get package name from filename
        uninstall_package(pkg_name)

        print(f" Installing: {apk.name}")
        result = subprocess.run(["adb", "install", str(apk.resolve())], capture_output=True, text=True)

        if result.returncode == 0 and "Success" in result.stdout:
            print(f" Installed: {apk.name}")
            package_names.append(pkg_name)
        else:
            print(f" Failed to install {apk.name}")
            print(f"Error: {result.stderr.strip()}")

    return package_names
