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

## Analysis Output

After each run, results are saved in:

### 1. Per-App Reports

Located in `output/`, each JSON file contains the app's events, score, verdict, and YARA matches.
  
    output/
    ├── com.example.app.json
    ├── net.sample.notes.json
    └── ...
   
### 2. Aggregated Report

All results are combined in a single file:
output/results.json

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

To run analysis with a specific Frida hook (e.g., readwrite), use:

```bash
python -m apk_inspector.main --hook readwrite --timeout 30
```

**Options:**

- `--hook <name>`: Select which hook to use (`readwrite`, `network`, etc.)
- `--timeout <seconds>`: Duration to trace app activity
- `--include-private`: Include private IPs in output (for network analysis)

---

## YARA Integration 

Place .yar rules in yara_rules/.
Example YARA rules can detect:
- AWS credentials (access key + secret)
- Firebase database URLs
- Other hardcoded secrets or keys
You can customize and add new rules easily.

### Automated YARA Test Assets
The repository includes pre-built test rules and files in:

```text
tests/
├── test_rules/      ← Contains YARA rules like `aws_test.yar`
├── test_files/      ← Contains matching files like `fake_creds.txt`

These are used for:

Unit testing the YARA engine
CI/CD validation of rule matching
Validating scan_with_yara() functionality

---

## Scoring & Verdicts

Each app is evaluated using a rule engine that assigns a suspicion score based on:

- Access to sensitive or private file paths
- API tokens or credentials in traffic
- Communication with public IPs
- High-volume data transfers

| Score Range | Verdict     |
|-------------|-------------|
| > 10        | Malicious   |
| 6–10        | Suspicious  |
| < 6         | Benign      |

---

## Testing & Development
You can run tests and manage development tools with either Python or Make:
### Using Python (cross-platform)

```bash
python tools/dev.py setup     # Generate test assets
python tools/dev.py test      # Run all tests
python tools/dev.py clean     # Delete test artifacts
```

### Using Make (Linux/macOS, or Git Bash on Windows)

```bash
make setup
make test
make clean
```

## Troubleshooting

- Frida not attaching? Check Frida server version matches Python version.
- Device not found? Run adb devices, enable USB debugging.
- YARA not working? Ensure yara CLI or libyara is installed.

---

## Project Structure

    apk-inspector/
    ├── apk_inspector/
    │   ├── main.py
    │   ├── core.py
    │   ├── cli.py
    │   └── utils/
    │       ├── adb_tools.py
    │       ├── apk_utils.py
    │       ├── classifier.py
    │       ├── file_utils.py
    │       ├── frida_utils.py
    │       ├── hook_utils.py
    │       ├── rule_engine.py
    │       ├── yara_scanner.py
    │       └── decompiler.py
    ├── frida_hooks/
    │   ├── hook_readwrite.js
    │   ├── hook_network.js
    ├── apks/
    ├── output/
    ├── yara_rules/
    │   └── aws_keys.yar
    ├── requirements.txt
    └── README.md

---

## License

MIT License

---

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.
