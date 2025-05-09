# APK Inspector

Dynamic Android APK tracer using Python + Frida

APK Inspector is a Python-based toolkit designed to:
- Install APKs to an Android device via ADB
- Dynamically trace which files are opened during app startup using Frida
- Output JSON logs of file access activity

## Features

- Bulk APK installation from a folder
- File-access tracing with Frida hooks (`open`, `openat`, etc.)
- Outputs results in JSON format for analysis
- Modular codebase (utilities, Frida scripts, main runner)

## Project Structure
```
apk-inspector/
├── apks/ # Input APKs (excluded from Git)
├── frida_hooks/ # Frida JavaScript hook files
├── utils/ # Python utility modules
├── output/ # JSON results from tracing
├── main.py # Entry point for processing
└── README.md
```
## Requirements

- Python 3.10+
- Frida (CLI and Python bindings)
- ADB (Android Debug Bridge)
- Rooted Android device (running Frida server)

## Usage

1. Place APKs into the `apks/` folder  
2. Start the Frida server on the target Android device  
3. Run: python main.py
4. Review file-open logs in `output/results.json`

## License

This project is licensed under the [MIT License](LICENSE).




