from setuptools import setup

setup(
    name="mcp-security-scanner",
    version="0.1.0",
    description="A comprehensive security auditing and fuzzing tool for Model Context Protocol (MCP) servers.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Arron",
    py_modules=["scanner"],
    install_requires=[
        "mcp>=1.0.0",
    ],
    entry_points={
        "console_scripts": [
            "mcp-scan=scanner:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
)
