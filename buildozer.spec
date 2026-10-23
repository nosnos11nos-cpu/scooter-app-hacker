[app]
title = ScooterTool
package.name = scootertool
package.domain = org.scooter
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,jar
version = 0.1

# Архитектура (arm64-v8a покрывает большинство современных телефонов)
android.archs = arm64-v8a

# Версии Android
android.api = 33
android.minapi = 21
android.ndk = 25b
android.ndk_api = 21
android.accept_sdk_license = True

# Разрешения
android.permissions = BLUETOOTH, BLUETOOTH_ADMIN, BLUETOOTH_SCAN, BLUETOOTH_CONNECT, BLUETOOTH_ADVERTISE, ACCESS_FINE_LOCATION

# Ветка develop обязательна для совместимости с pyjnius
p4a.branch = develop

# КЛЮЧЕВОЕ: фиксируем версии Python, Cython, OpenSSL, cryptography и pyjnius
requirements = python3==3.10.11,hostpython3==3.10.11,kivy,openssl==3.0.16,cryptography==42.0.5,pyjnius @ git+https://github.com/kivy/pyjnius.git@eaf76a5#egg=pyjnius,pycryptodome,requests

[buildozer]
log_level = 2
warn_on_root = 1
