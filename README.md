# APK Inspector

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/alpha-early--access-orange)

**APK Inspector** is a powerful Python-based toolkit for static and dynamic analysis of Android APKs. Built for malware analysts, SOC teams, and reverse engineers, it combines Frida-based runtime instrumentation with static YARA rule scanning to identify suspicious behaviors and generate actionable reports.

---

## Features

- **Dynamic analysis** with Frida:
  - Monitor file system and network activity
  - Hook runtime functions (e.g., `open`, `send`, `dlopen`, `System.loadLibrary`)
- **Static analysis** of decompiled APKs:
  - Extract manifest permissions, components, and exported services
  - Detect dangerous permissions and misconfigurations
- **YARA-based scanning** of:
  - Decompiled smali code
  - Embedded strings and assets
  - APK structure and behaviors
- **Scoring engine**:
  - Assigns a risk score and verdict (`benign`, `suspicious`, `malicious`)
  - Supports customizable rule weights and CVSS-style banding
- **Automated reporting**:
  - JSON, CSV, and HTML dashboards
  - Includes per-APK and global analysis summaries

---

## Getting Started

### 1. Prerequisites

- Python 3.9+ installed
- A rooted Android device or emulator with:
  - USB debugging enabled (Settings > Developer Options)
  - Frida server running on the device
- Tools:
  - `adb`, `frida-tools`, `aapt`, `apktool`
  - `yara-python` for static scanning

### Install Required Tools

```bash
pip install -r requirements.txt
pip install frida-tools yara-python

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
apk-inspector
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
