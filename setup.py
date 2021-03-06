import setuptools

setuptools.setup(
  name = 'beaconscanner',
  packages = ['beaconscanner'],
  version = '1.2.6',  
  license='MIT',
  description = 'Scan and decode ble data',
  author = 'theBASTI0N',
  author_email = 'theBASTI0Ncode@gmail.com',
  url = 'https://github.com/theBASTI0N/beaconscanner',
  download_url = 'https://github.com/theBASTI0N/beaconscanner/archive/1.2.6.tar.gz',
  keywords = ['BLE', 'decode', 'iot'],
  install_requires=['beacondecoder', 'uptime', 'pyserial'],
  classifiers=[
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Programming Language :: Python :: 3.7',
  ],
)