from setuptools import setup

setup(
    name="xssentry",
    version="4.0",
    description="Autonomous XSS Hunter [HELLHOUND-class]",
    author="Hellhound Security",
    py_modules=["xssentry", "spider"],
    entry_points={
        "console_scripts": [
            "xssentry-bin=xssentry:main",
        ],
    },
    install_requires=[
        "playwright",
        "aiohttp",
        "beautifulsoup4",
        "lxml",
    ],
    python_requires=">=3.7",
)
