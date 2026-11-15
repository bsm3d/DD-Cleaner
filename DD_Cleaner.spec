# -*- mode: python ; coding: utf-8 -*-
#
# One-folder build (not one-file). The program always runs as administrator: a one-file exe unpacks itself
# into %TEMP%\_MEIxxxx, a folder the user's non-elevated processes can write, so malware running as the
# user could swap a DLL there and have it loaded as administrator. Install the dist\DD_Cleaner folder under
# C:\Program Files\ instead (only administrators can change it; the program warns if it is elsewhere).


a = Analysis(
    ['DD_Cleaner.py'],
    pathex=[],
    binaries=[],
    datas=[('ddcleaner/data/world_countries.json', 'ddcleaner/data'),
           ('ddcleaner/data/dd_cleaner.png', 'ddcleaner/data')],
    hiddenimports=['security_audit'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='DD_Cleaner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['ddcleaner/data/dd_cleaner.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='DD_Cleaner',
)
