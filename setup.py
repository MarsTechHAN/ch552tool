import setuptools

setuptools.setup(
    name="ch55xtool",
    version="0.0.2",
    author="Han Xiao",
    author_email="hansh-sz@hotmail.com",
    description="An open sourced python tool for flashing WCH CH55x series USB microcontroller",
    url="https://github.com/MarsTechHAN/ch552tool",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points = {
        'console_scripts': [
            'ch55xtool = ch55xtool.ch55xtool:main'
        ]
    },
    python_requires='>=3.5',
    install_requires=['pyusb>=1.0.0'])
