import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("❌ 缺少库，请运行: pip install cryptography")
    input("回车退出...")
    sys.exit(1)

# ===== 获取脚本/exe 所在目录 =====
def get_base_dir():
    if getattr(sys, 'frozen', False):
        # 打包成 exe 后，用 sys.executable 获取 exe 所在目录
        return os.path.dirname(os.path.abspath(sys.executable))
    else:
        # 普通 Python 脚本
        return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()

# ===== OpenSSL 兼容格式常量 =====
OPENSSL_MAGIC = b'Salted__'
SALT_SIZE = 8
KEY_SIZE = 32
IV_SIZE = 16
ITERATIONS = 480000

# ===== 密钥派生 =====
def derive_key_iv(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + IV_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    derived = kdf.derive(password.encode('utf-8'))
    return derived[:KEY_SIZE], derived[KEY_SIZE:]

# ===== 密码管理（🌟 修复：使用 BASE_DIR）=====
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

# ===== 检测是否已加密 =====
def is_encrypted(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read(8) == OPENSSL_MAGIC
    except:
        return False

# ===== 加密 =====
def encrypt_file(filepath, password):
    if is_encrypted(filepath):
        return False, "已加密，跳过"

    with open(filepath, 'rb') as f:
        data = f.read()

    salt = os.urandom(SALT_SIZE)
    key, iv = derive_key_iv(password, salt)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    encrypted = enc.update(padded) + enc.finalize()

    tmp = filepath + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(OPENSSL_MAGIC)
        f.write(salt)
        f.write(encrypted)

    os.replace(tmp, filepath)
    return True, "🔒 加密"

# ===== 解密 =====
def decrypt_file(filepath, password):
    if not is_encrypted(filepath):
        return False, "未加密，跳过"

    with open(filepath, 'rb') as f:
        f.read(8)
        salt = f.read(SALT_SIZE)
        encrypted = f.read()

    key, iv = derive_key_iv(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(encrypted) + dec.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    try:
        data = unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        return False, "密码错误"

    tmp = filepath + '.tmp'
    with open(tmp, 'wb') as f:
        f.write(data)

    os.replace(tmp, filepath)
    return True, "🔓 解密"

# ===== 自动判断 =====
def process_file(filepath, password):
    if is_encrypted(filepath):
        return decrypt_file(filepath, password)
    else:
        return encrypt_file(filepath, password)

# ===== 主程序 =====
def main():
    print("=" * 55)
    print("🔐 AES-256 一键加密/解密 (兼容 OpenSSL)")
    print("   加密后文件名不变，任何系统都能解密")
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
                    fp = os.path.join(root, f)
                    if fp.endswith('.tmp'):
                        continue
                    files.append(fp)

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

    print("\n📋 紧急解密（无Python时，在终端执行）:")
    print("   Mac/Linux:")
    print("   openssl enc -d -aes-256-cbc -pbkdf2 -iter 480000 \\")
    print("     -in 加密文件 -out 输出文件")
    print(f"{'=' * 55}")
    input("\n回车退出...")

if __name__ == "__main__":
    main()