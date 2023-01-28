import setuptools

setuptools.setup(
    name="ch55xtool",
    version="1.0.4",
    author="Han Xiao",
    author_email="hansh-sz@hotmail.com",
    maintainer="https://github.com/MarsTechHAN/ch552tool/graphs/contributors",
    maintainer_email="hansh-sz@hotmail.com",
    description="An open sourced python tool for flashing WCH CH55x series USB microcontroller",
    long_description=open("README.rst").read(),
    long_description_content_type="text/x-rst",
    url="https://github.com/MarsTechHAN/ch552tool",
    packages=setuptools.find_packages(),
    package_data={'ch55xtool': ['*.wcfg', 'ch55xtool/*.wcfg']},
    include_package_data=True,
    platforms=["all"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Environment :: Console",
        "Natural Language :: English",
        "Programming Language :: Python",
        "Programming Language :: Python :: Implementation",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Software Development :: Embedded Systems",
    ],
    entry_points = {
        'console_scripts': [
            'ch55xtool = ch55xtool.ch55xtool:main'
        ]
    },
    python_requires='>=3.5',
    install_requires=['pyusb>=1.0.0'])
