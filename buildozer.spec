[app]
title = ScooterHack
package.name = scooterhack
package.domain = org.scooter
source.dir = .
source.include_exts = py,png,jpg,kv,atlas,jar
version = 1.0
requirements = python3,kivy,pyjnius,pycryptodome,cryptography,requests
orientation = portrait
fullscreen = 1

android.permissions = BLUETOOTH, BLUETOOTH_ADMIN, BLUETOOTH_SCAN, BLUETOOTH_CONNECT, ACCESS_FINE_LOCATION
android.api = 33
android.minapi = 21
android.ndk = 25b
android.accept_sdk_license = True
android.archs = arm64-v8a

[buildozer]
log_level = 2
warn_on_root = 1
