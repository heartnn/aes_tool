import os
import sys
import time

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("❌ 缺少库，请运行: pip install cryptography")
    input("回车退出...")
    sys.exit(1)

# ===== 配置 =====
ENCRYPT_SIZE = 4096
MAGIC = b'HEAD'
SALT_SIZE = 8
NONCE_SIZE = 16
TRAILER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE  # 28 bytes
ITERATIONS = 10000  # PBKDF2 迭代次数

# ===== 获取脚本/exe 所在目录 =====
def get_base_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()

# ===== 密码管理 =====
def get_password():
    pwd_file = os.path.join(BASE_DIR, "password.txt")
    if os.path.exists(pwd_file):
        with open(pwd_file, 'r', encoding='utf-8') as f:
            pwd = f.read().strip()
            if pwd:
                return pwd
    pwd = input("🔑 首次使用，请输入密码: ").strip()
    if not pwd:
        print("❌ 密码不能为空")
        sys.exit(1)
    with open(pwd_file, 'w', encoding='utf-8') as f:
        f.write(pwd)
    print("✅ 密码已保存到 password.txt")
    return pwd

# ===== 密钥派生 =====
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))

# ===== 检测是否已加密 =====
def is_encrypted(filepath):
    try:
        size = os.path.getsize(filepath)
        if size < TRAILER_SIZE:
            return False
        with open(filepath, 'rb') as f:
            f.seek(size - TRAILER_SIZE)
            return f.read(4) == MAGIC
    except:
        return False

# ===== 读取末尾标记 =====
def read_trailer(filepath):
    size = os.path.getsize(filepath)
    with open(filepath, 'rb') as f:
        f.seek(size - TRAILER_SIZE)
        magic = f.read(4)
        if magic != MAGIC:
            return None, None
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
    return salt, nonce

# ===== 加密 =====
def encrypt_file(filepath, password):
    file_size = os.path.getsize(filepath)
    if file_size == 0:
        return False, "空文件，跳过"
    if is_encrypted(filepath):
        return False, "已加密，跳过"

    enc_size = min(ENCRYPT_SIZE, file_size)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    with open(filepath, 'r+b') as f:
        data = f.read(enc_size)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        enc = cipher.encryptor()
        encrypted = enc.update(data) + enc.finalize()
        f.seek(0)
        f.write(encrypted)
        f.seek(0, 2)
        f.write(MAGIC)
        f.write(salt)
        f.write(nonce)

    return True, "🔒 加密"

# ===== 解密 =====
def decrypt_file(filepath, password):
    if not is_encrypted(filepath):
        return False, "未加密，跳过"

    file_size = os.path.getsize(filepath)
    data_size = file_size - TRAILER_SIZE

    salt, nonce = read_trailer(filepath)
    if salt is None:
        return False, "标记损坏"

    key = derive_key(password, salt)
    enc_size = min(ENCRYPT_SIZE, data_size)

    with open(filepath, 'r+b') as f:
        data = f.read(enc_size)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        dec = cipher.decryptor()
        decrypted = dec.update(data) + dec.finalize()
        f.seek(0)
        f.write(decrypted)

    with open(filepath, 'r+b') as f:
        f.truncate(data_size)

    return True, "🔓 解密"

# ===== 自动判断 =====
def process_file(filepath, password):
    if is_encrypted(filepath):
        return decrypt_file(filepath, password)
    else:
        return encrypt_file(filepath, password)

# ===== 紧急解密方法 =====
def print_emergency_methods():
    print("\n" + "=" * 55)
    print("📋 紧急解密方法（无 exe / 无本脚本时）")
    print("=" * 55)
    print(f"""
━━━ 文件格式说明 ━━━

加密后文件结构:
  [前4KB密文] [剩余数据不动] [HEAD][salt 8字节][nonce 16字节]
                              |<-------- 末尾 28 字节 -------->|

解密参数:
  算法: AES-256-CTR
  密钥: PBKDF2-HMAC-SHA256(密码, salt, {ITERATIONS}次迭代) → 32字节
  Nonce: 末尾标记中的 16 字节
  解密范围: 仅前 {ENCRYPT_SIZE} 字节
  解密后: 删除末尾 28 字节

━━━ 方法 1: Python 一行命令 (全平台通用) ━━━

python3 -c "
import sys
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
f,p=sys.argv[1],sys.argv[2]
d=open(f,'rb').read();t=d[-28:];salt=t[4:12];nonce=t[12:28];sz=len(d)-28
es=min({ENCRYPT_SIZE},sz)
kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations={ITERATIONS})
k=kdf.derive(p.encode())
c=Cipher(algorithms.AES(k),modes.CTR(nonce)).decryptor()
r=c.update(d[:es])+c.finalize()
open(f,'wb').write(r+d[es:sz])
print('OK')
" "加密文件路径" "你的密码"

━━━ 方法 2: Linux Bash 脚本 ━━━
保存为 decrypt.sh，chmod +x decrypt.sh，运行 ./decrypt.sh 文件 密码

#!/bin/bash
FILE="$1"; PASS="$2"
python3 -c "
import sys
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
f,p='$FILE','$PASS'
d=open(f,'rb').read();t=d[-28:];salt=t[4:12];nonce=t[12:28];sz=len(d)-28
es=min({ENCRYPT_SIZE},sz)
kdf=PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations={ITERATIONS})
k=kdf.derive(p.encode())
c=Cipher(algorithms.AES(k),modes.CTR(nonce)).decryptor()
r=c.update(d[:es])+c.finalize()
open(f,'wb').write(r+d[es:sz])
print('✅ 解密成功:',f)
"

━━━ 方法 3: Windows PowerShell ━━━
保存为 decrypt.ps1，运行: .\\decrypt.ps1 "文件路径" "密码"

param([string]$F, [string]$P)
$b=[IO.File]::ReadAllBytes($F)
$salt=$b[($b.Length-24)..($b.Length-17)]
$nonce=$b[($b.Length-16)..($b.Length-1)]
$sz=$b.Length-28; $es=[Math]::Min({ENCRYPT_SIZE},$sz)
$pb=New-Object Security.Cryptography.Rfc2898DeriveBytes($P,$salt,{ITERATIONS},[Security.Cryptography.HashAlgorithmName]::SHA256)
$key=$pb.GetBytes(32)
$aes=[Security.Cryptography.Aes]::Create()
$aes.Key=$key;$aes.Mode='CTR';$aes.Padding='None';$aes.IV=$nonce
$dec=$aes.CreateDecryptor().TransformFinalBlock($b,0,$es)
$fs=[IO.File]::OpenWrite($F)
$fs.Write($dec,0,$es);$fs.SetLength($sz);$fs.Close()
Write-Host "✅ 解密成功" -Fore Green
""")
    print("=" * 55)

# ===== 等待按键（3秒超时）=====
def wait_for_key(timeout=3):
    """等待用户按键，超时返回 None"""
    print(f"\n⏳ {timeout} 秒后自动退出 | 按任意键显示紧急解密方法...")

    if sys.platform == 'win32':
        import msvcrt
        end_time = time.time() + timeout
        while time.time() < end_time:
            if msvcrt.kbhit():
                msvcrt.getch()
                return True
            time.sleep(0.05)
        return None
    else:
        import select
        import termios
        import tty
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            rlist, _, _ = select.select([sys.stdin], [], [], timeout)
            if rlist:
                sys.stdin.read(1)
                return True
        except Exception:
            # 非终端环境（如管道），退化为普通 input
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return None

# ===== 主程序 =====
def main():
    print("=" * 55)
    print("⚡ 极速加密/解密 (仅加密前4KB·原地修改·零拷贝)")
    print(f"   加密大小: {ENCRYPT_SIZE}B | PBKDF2: {ITERATIONS}次")
    print("=" * 55)

    password = get_password()

    if len(sys.argv) > 1:
        paths = sys.argv[1:]
        print(f"\n📥 拖入 {len(paths)} 个目标")
    else:
        ui = input("\n📂 拖入文件/文件夹，或粘贴路径后回车:\n> ").strip().strip('"').strip("'")
        if not ui:
            return
        paths = [ui]

    ok = skip = fail = 0

    for path in paths:
        path = os.path.abspath(path)
        if not os.path.exists(path):
            print(f"⚠️ 不存在: {path}")
            continue

        if os.path.isfile(path):
            files = [path]
        else:
            files = []
            for root, _, fs in os.walk(path):
                for f in fs:
                    files.append(os.path.join(root, f))

        print(f"\n📂 {os.path.basename(path)} ({len(files)} 个文件)")

        for i, fp in enumerate(files, 1):
            fname = os.path.basename(fp)
            try:
                success, msg = process_file(fp, password)
                if success:
                    print(f"  [{i}/{len(files)}] {msg} ✅ {fname}")
                    ok += 1
                else:
                    print(f"  [{i}/{len(files)}] ⏭️ {fname} → {msg}")
                    skip += 1
            except Exception as e:
                print(f"  [{i}/{len(files)}] ❌ {fname} → {e}")
                fail += 1

    print(f"\n{'=' * 55}")
    print(f"🎉 完成！  ✅ {ok} | ⏭️ {skip} | ❌ {fail}")
    print(f"{'=' * 55}")

    # 等待 3 秒，有按键则显示紧急解密方法
    key_pressed = wait_for_key(3)
    if key_pressed:
        print_emergency_methods()
        input("\n按回车退出...")
    # 无按键则直接退出（不显示任何提示）

if __name__ == "__main__":
    main()