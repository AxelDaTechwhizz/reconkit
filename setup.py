from setuptools import setup, find_packages

def load_requirements(path):
    with open(path, "r") as f:
        lines = f.read().splitlines()
        return [line.strip() for line in lines if line.strip() and not line.startswith("#") and not line.startswith("-")]


setup(
    name="reconkit",
    version="2.1.0",
    author="NyxSynn",
    description="Modular recon tool for web enumeration, tech detection, and CVE scanning",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/AxelDaTechwhizz/reconKit",
    packages=find_packages(),
    include_package_data=True,
    install_requires=load_requirements("requirements-base.txt"),
    entry_points={
        'console_scripts': [
            'reconkit=reconkit.cli:app',   # entry -> reconkit/cli.py -> `app` object
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
    ],
    python_requires='>=3.7',
)