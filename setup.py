from setuptools import setup, find_packages

setup(
    name="flaghunter",
    version="1.5.0",
    author="Rashid",
    description="Advanced CTF Static Analysis & Deep Scan Tool",
    long_description=open("README.md").read() if hasattr(open("README.md"), "read") else "",
    long_description_content_type="text/markdown",
    packages=find_packages(),
    py_modules=["flaghunter"],
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'flaghunter=flaghunter:main',  # This creates the terminal command
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
