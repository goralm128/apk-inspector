# APK Inspector

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/alpha-early--access-orange)

**APK Inspector** is a Python-based toolkit for dynamic and static analysis of Android APKs. It uses [Frida](https://frida.re/) to trace real-time behavior, classifies suspicious activity, scans for malware indicators using YARA, and automatically generates structured JSON verdicts — making it ideal for reverse engineers, SOC analysts, and mobile security researchers.

---

## Features

- Install and launch multiple APKs automatically via `adb`
- Trace runtime behavior with Frida:
  - File access (e.g., `read`, `write`, `fopen`)
  - Network traffic (e.g., `send`, `recv`, `connect`, TLS hooks)
- Automatically classify accessed data (e.g., `sensitive`, `auth`, `config`)
- Assign a suspicion score and generate a verdict (`benign`, `suspicious`, or `malicious`)
- Decompile APKs and scan them using custom YARA rules
- Output structured per-app and aggregated JSON reports

---

## Getting Started

### 1. Prerequisites

- Python 3.9+ installed
- A rooted Android device or emulator with:
  - USB debugging enabled (Settings > Developer Options)
  - Frida server running on the device
- `adb` installed and in your system `PATH`
- `frida-tools` installed:

```bash
pip install frida-tools
```

- aapt in your PATH for faster APK analysis
- Manually install ApkTool: https://ibotpeaches.github.io/Apktool/

### 2. Prepare the Device

- Rooted Device: Ensure your device is rooted (e.g., Magisk).
- Push Frida Server:
    - Download the appropriate Frida server binary for your device architecture (e.g., frida-server-16.1.4-android-arm64).
    - Push it to your device:

        ```bash
        adb push frida-server /data/local/tmp/
        adb shell "chmod 755 /data/local/tmp/frida-server"
        ```

    - Start Frida Server (in a root shell):

        ```bash
        su
        /data/local/tmp/frida-server &
        ```

    - Verify it’s running:

        ```bash
        frida-ps -U
        ```
---

### 3. Setup

- Clone the repository and install dependencies:
    ```bash
    git clone https://github.com/goralm128/apk-inspector
    cd apk-inspector
    ```

- Place your .apk files in the apks/ directory.

---

### 4. Running the Tool

Install the tool and its dependencies:

```bash
pip install .
```

To run analysis use:

```bash
apk-inspector --apk-dir apks --output-dir output --hooks-dir frida_hooks
```

**Options:**

- `--hook <name>`: Select which hook to use (`readwrite`, `network`, etc.)
- `--timeout <seconds>`: Duration to trace app activity
- `--include-private`: Include private IPs in output (for network analysis)

---

## Scoring & Verdicts

Each app is evaluated using a rule engine that assigns a suspicion score based on:

- Access to sensitive or private file paths
- API tokens or credentials in traffic
- Communication with public IPs
- High-volume data transfers

## Troubleshooting

- Frida not attaching? Check Frida server version matches Python version.
- Device not found? Run adb devices, enable USB debugging.
- YARA not working? Ensure yara CLI or libyara is installed.

---

## License

MIT License

---

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.
