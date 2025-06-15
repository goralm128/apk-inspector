from setuptools import setup, find_packages
from pathlib import Path

here = Path(__file__).parent
long_description = (here / "README.md").read_text(encoding="utf-8")

setup(
    name="apk-inspector",
    version="0.1.0",
    description="Toolkit for dynamic and static analysis of Android APKs using Frida and YARA",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Maya Gorel",
    author_email="maya.gorel@gmail.com",
    url="https://github.com/goralm128/apk-inspector",

    packages=find_packages(exclude=["tests*", "examples*", "docs*"]),
    include_package_data=True,
    python_requires=">=3.10,<3.11",

    install_requires=[
        "frida==17.1.2",
        "frida-tools==14.1.1",
        "yara-python>=4.3.1",
        "jsonschema>=4.0.0",
        "adb-shell>=0.4.0",
        "androguard>=3.3.5",
        "pydantic>=2.6.0",
        "pandas>=2.2.0",
        "jinja2>=3.1.0",
        "plotly>=5.0.0",
        "matplotlib>=3.8.0",
        "lxml>=5.2.0"
    ],

    entry_points={
        "console_scripts": [
            "apk-inspector=apk_inspector.main:main"
        ]
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "Topic :: Software Development :: Build Tools",
    ],

    keywords="android apk analysis frida yara static dynamic reverse-engineering",
    license="MIT",
)
