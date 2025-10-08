"""
Setup script for MapacheSPIM Python package
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="mapachespim",
    version="0.1.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Educational RISC-V Assembly Debugger with SPIM-like Interface",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/MapacheSPIM",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Education",
        "Topic :: Education",
        "Topic :: Software Development :: Debuggers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "mapachespim=mapachespim.console:main",
        ],
    },
    install_requires=[
        "pyelftools>=0.29",  # ELF file parsing for section inspection
    ],
)
