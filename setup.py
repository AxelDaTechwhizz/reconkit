from setuptools import setup, find_packages

setup(
    name="reconkit",
    version="1.0.0",
    author="NyxSynn",
    description="Modular recon tool for web enumeration, tech detection, and CVE scanning",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/AxelDaTechwhizz/ReconKit",
    packages=find_packages(),
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
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
