#!/usr/bin/env python
from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')
requirements = (this_directory / "requirements.txt").read_text().splitlines()

setup(
    name="fortiaudit",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Comprehensive Security Audit Tool for Fortinet FortiGate",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/fortiaudit",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "fortiaudit=fortiaudit.cli:main",
        ],
    },
    include_package_data=True,
)
