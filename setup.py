from setuptools import setup, find_packages

setup(
    name="AndroidManifestExplorer",
    version="1.0.0",
    author="Mateo Fumis",
    author_email="mateofumis@mfumis.com",
    description="A professional tool to automate attack surface detection in Android applications by parsing Manifest files.",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/mateofumis/AndroidManifestExplorer",
    packages=find_packages(),
    py_modules=["AndroidManifestExplorer"],
    install_requires=[
        "colorama>=0.4.4",
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
