from setuptools import setup, find_packages

setup(
    name="apk-inspector",
    version="0.1.0",
    description="A Python-based toolkit for dynamic and static analysis of Android APKs using Frida and YARA.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Maya Gorel",
    author_email="maya.gorel@gmail.com",
    url="https://github.com/goralm128/apk-inspector",
    packages=find_packages(exclude=["tests*", "examples*", "docs*"]),
    python_requires=">=3.8",
    install_requires=[
        "frida==16.2.2",  # compatible with Frida 16.x
        "frida-tools==12.4.0",  # compatible with Frida 16.x
        "yara-python",
        "jsonschema>=4.0.0",
        "adb-shell",
        "androguard"
    ],
    entry_points={
        "console_scripts": [
            "apk-inspector=apk_inspector.main:main"
        ]
    },
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
    ],
    keywords="android apk analysis frida yara static dynamic reverse-engineering",
    license="MIT",
)
