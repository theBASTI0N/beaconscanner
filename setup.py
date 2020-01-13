from distutils.core import setup
setup(
  name = 'pybluez2mqtt',
  packages = ['pybluez2mqtt'],
  version = '0.1',  
  license='MIT',
  description = 'Scan, decode and send ble data',
  author = 'theBASTI0N',
  author_email = 'theBASTI0Ncode@gmail.com',
  url = 'https://github.com/theBASTI0N/pybluez2mqtt',
  download_url = 'https://github.com/theBASTI0N/pybluez2mqtt/archive/0.1.tar.gz',
  keywords = ['BLE', 'decode', 'iot'],
  install_requires=['uptime',
          'paho.mqtt',
          'beacon-decoder'],
  classifiers=[
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3.7'
  ],
)