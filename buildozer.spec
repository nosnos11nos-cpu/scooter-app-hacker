[app]
title = ScooterTool
package.name = scootertool
package.domain = org.scooter
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,jar
version = 0.1

# ВАЖНО: Только 64-битная архитектура (на современных телефонах этого достаточно)
android.archs = arm64-v8a

# Фиксируем версии, чтобы сборка не сломалась
android.api = 33
android.minapi = 21
android.ndk = 25b
android.ndk_api = 21
android.accept_sdk_license = True
android.allow_backup = True

# Железно прописываем разрешения
android.permissions = BLUETOOTH, BLUETOOTH_ADMIN, BLUETOOTH_SCAN, BLUETOOTH_CONNECT, BLUETOOTH_ADVERTISE, ACCESS_FINE_LOCATION

# Ветка develop нужна для свежего pyjnius
p4a.branch = develop

# Добавляем setuptools для сборки C-библиотек
requirements = python3,kivy,pyjnius,pycryptodome,cryptography,requests,setuptools

[buildozer]
log_level = 2
warn_on_root = 1
