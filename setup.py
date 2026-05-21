from setuptools import setup, find_packages

setup(
    name="arachne",
    version="2.0.0",
    description="ARACHNE — web vulnerability scanner: XSS, SQLi, SSRF, LFI, RCE, CORS, CSRF + ML",
    author="oliviaisntcringe",
    url="https://github.com/oliviaisntcringe/security-scanner",
    packages=find_packages(exclude=["tests*", "training_data*"]),
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9",
        "beautifulsoup4>=4.12",
        "click>=8.1",
        "rich>=13.0",
        "prompt_toolkit>=3.0",
        "dnspython>=2.4",
        "requests>=2.31",
        "fake-useragent>=1.1",
        "scikit-learn>=1.2",
        "numpy>=1.20",
        "joblib>=1.1",
    ],
    entry_points={
        "console_scripts": [
            "arachne=scanner.cli:main",
        ],
    },
    include_package_data=True,
)
