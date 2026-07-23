from setuptools import setup

setup(
    name="AndroidManifestExplorer",
    version="2.1.0",
    author="Mateo Fumis",
    author_email="mateofumis@mfumis.com",
    description="A professional tool to automate attack surface detection in Android applications by parsing Manifest files.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mateofumis/AndroidManifestExplorer",
    py_modules=["AndroidManifestExplorer"],
    install_requires=[
        "rich==13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "AndroidManifestExplorer=AndroidManifestExplorer:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Intended Audience :: Information Technology",
        "Environment :: Console",
    ],
    python_requires=">=3.6",
)
