# APK Inspector

A Python-based tool to install Android APKs, launch them, and trace file access using [Frida](https://frida.re/) — with zero user interaction.

# Features

- Install multiple APKs automatically via `adb`
- Launch apps automatically (no user interaction)
- Trace system calls using Frida:
  - Native file reads/writes (`read`, `write`, `fread`, etc.)
  - Network connections (via socket, connect)
  - File open events (`open`, `openat`, `fopen`, etc.)
- Log all file paths accessed during app startup
- Export results to structured JSON

## Results

After tracing completes, results are saved in two ways:

1. **Per-App Reports**  
   Located in the `output/` folder, one JSON file per package:
  
    output/
    ├── com.example.app.json
    ├── net.sample.notes.json
    └── ...
   
2. **Aggregated Report**  
    All results combined in a single file: results.json

# Project Structure

    apk-inspector/
    ├── apk_inspector/
    │   ├── core.py
    │   ├── main.py
    │   ├── cli.py
    │   ├── utils/
    │   │   ├── adb_tools.py
    │   │   ├── apk_utils.py
    │   │   ├── classifier.py
    │   │   ├── file_utils.py
    │   │   ├── frida_utils.py
    │   │   └── hook_utils.py
    ├── frida_hooks/
    │   ├── hook_readwrite.js
    │   ├── hook_network.js
    │   └── ...
    ├── tests/
    │   ├── test_classifier.py
    │   └── ...
    ├── output/
    │   ├── com.example.app.json
    │   └── results.json
    ├── requirements.txt
    └── README.md

# Getting Started

    1. Prerequisites

        Before running APK Inspector, ensure the following:

        - Python 3.9+ installed

        - An Android device or emulator with:

            USB debugging enabled (Settings > Developer Options)
            Root access (required for Frida to attach to apps)
            Frida server running on the device

        - adb installed and available in your system PATH

        - frida-tools installed on your PC:
            pip install frida-tools
        - aapt in your PATH for faster APK analysis

    2. Prepare the Device

        - Rooted Device: Ensure your device is rooted (e.g., Magisk).

        - Push Frida Server:

            Download the appropriate Frida server binary for your device architecture (e.g., frida-server-16.1.4-android-arm64).
            Push it to your device:
            adb push frida-server /data/local/tmp/
            adb shell "chmod 755 /data/local/tmp/frida-server"
            
        - Start Frida Server (in a root shell):
            su
            /data/local/tmp/frida-server &
        - Verify it’s running:
            frida-ps -U


    3. Setup

        Clone the repository and install dependencies:
        
            git clone https://github.com/goralm128/apk-inspector
            cd apk-inspector

        Place your .apk files in the apks/ directory.

    4. Running the Tool

        To run analysis with a specific Frida hook (e.g., readwrite), use:

        python -m apk_inspector.main --hook readwrite --timeout 30

        Options:

            --hook <name>: Select which hook to use (readwrite, network, etc.)

            --timeout <seconds>: Duration to trace app activity

            --include-private: Include private IP addresses in output (for network analysis)

## Troubleshooting

- **Frida not attaching?** Make sure the server version matches your Python Frida version.
- **ADB device not found?** Check USB debugging and `adb devices`.

## License

MIT License

## Contributing

Contributions are welcome! Feel free to open issues or pull requests.
