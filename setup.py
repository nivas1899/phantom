from setuptools import setup, find_packages

setup(
    name="phantom",
    version="1.0.0",
    description="Inter-Layer Semantic Gap Exploitation Framework",
    author="PHANTOM Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "httpx[http2]>=0.27.0",
        "rich>=13.7.0",
        "click>=8.1.7",
        "h2>=4.1.0",
    ],
    entry_points={
        "console_scripts": [
            "phantom=cli:cli",
        ],
    },
)
