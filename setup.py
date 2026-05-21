from setuptools import setup, find_packages

setup(
    name="vulnscan",
    version="2.0.0",
    description="Web vulnerability scanner — XSS, SQLi, CSRF, SSRF, LFI, RCE, CORS + ML detection",
    packages=find_packages(exclude=["tests*", "training_data*"]),
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9",
        "beautifulsoup4>=4.12",
        "click>=8.1",
        "rich>=13.0",
        "dnspython>=2.4",
        "requests>=2.31",
        "fake-useragent>=1.1",
        "scikit-learn>=1.2",
        "numpy>=1.20",
        "joblib>=1.1",
    ],
    entry_points={
        "console_scripts": [
            "vulnscan=scanner.cli:main",
        ],
    },
    include_package_data=True,
)
