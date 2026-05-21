from setuptools import setup, find_packages

setup(
    name="arachne",
    version="2.0.0",
    description="ARACHNE — web vulnerability framework: XSS, SQLi, SSRF, LFI, RCE, CORS, CSRF + ML",
    readme="README.md",
    license="MIT",
    author="oliviaisntcringe",
    url="https://github.com/oliviaisntcringe/security-scanner",
    packages=find_packages(exclude=["tests*", "training_data*", "*.egg-info"]),
    python_requires=">=3.9",
    install_requires=[
        # Core HTTP + parsing
        "aiohttp>=3.9",
        "beautifulsoup4>=4.12",
        "certifi>=2023.11",
        "charset-normalizer>=3.3",
        "idna>=3.6",
        "urllib3>=1.26,<3.0",
        "dnspython>=2.4",
        "requests>=2.31",
        "fake-useragent>=1.1",
        # CLI + output
        "click>=8.1",
        "rich>=13.0",
        "prompt_toolkit>=3.0",
        # ML
        "scikit-learn>=1.2",
        "numpy>=1.20",
        "joblib>=1.1",
    ],
    extras_require={
        "web": [
            "flask>=2.0,<3.0",
            "flask-socketio>=5.1",
            "python-socketio>=5.4",
            "werkzeug>=2.0,<3.0",
            "jinja2>=3.0",
        ],
        "telegram": [
            "python-telegram-bot>=20.0",
        ],
        "all": [
            "flask>=2.0,<3.0",
            "flask-socketio>=5.1",
            "python-socketio>=5.4",
            "werkzeug>=2.0,<3.0",
            "jinja2>=3.0",
            "python-telegram-bot>=20.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "arachne=scanner.cli:main",
        ],
    },
    include_package_data=True,
)
