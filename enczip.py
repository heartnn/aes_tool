import os
import sys
import shutil

try:
    import pyzipper
except ImportError:
    print("❌ 缺少 pyzipper，请运行: pip install pyzipper")
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

# ===== 检测是否是 ZIP 格式 =====
def is_zip_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read(4) == b'PK\x03\x04'
    except:
        return False

# ===== 加密 =====
def encrypt_file(filepath, password):
    tmp = filepath + ".tmp.zip"
    try:
        with pyzipper.AESZipFile(
            tmp, 'w',
            compression=pyzipper.ZIP_STORED,
            encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.write(filepath, arcname=os.path.basename(filepath))

        # 验证加密
        try:
            with pyzipper.AESZipFile(tmp, 'r') as zf:
                for name in zf.namelist():
                    zf.read(name)
            os.remove(tmp)
            return False, "加密失败：无密码也能读取"
        except Exception:
            pass

        os.remove(filepath)
        os.rename(tmp, filepath)
        return True, "🔒 加密"

    except Exception as e:
        if os.path.exists(tmp):
            os.remove(tmp)
        return False, str(e)

# ===== 解密 =====
def decrypt_file(filepath, password):
    tmp = filepath + ".tmp.zip"
    tmp_dir = filepath + ".tmp_dir"

    os.rename(filepath, tmp)

    try:
        os.makedirs(tmp_dir, exist_ok=True)
        with pyzipper.AESZipFile(tmp, 'r') as zf:
            zf.setpassword(password.encode('utf-8'))
            zf.extractall(path=tmp_dir)

        extracted = os.listdir(tmp_dir)
        for fname in extracted:
            src = os.path.join(tmp_dir, fname)
            dst = os.path.join(os.path.dirname(os.path.abspath(tmp)), fname)
            if os.path.exists(dst):
                os.remove(dst)
            shutil.move(src, dst)

        shutil.rmtree(tmp_dir)
        os.remove(tmp)
        return True, "🔓 解密"

    except Exception as e:
        if os.path.exists(tmp):
            try:
                os.rename(tmp, filepath)
            except:
                pass
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        return False, f"解密失败: {e}"

# ===== 全自动判断 =====
def auto_process(filepath, password):
    """
    判断逻辑：
    1. 不是 ZIP 格式 → 普通文件 → 加密
    2. 是 ZIP 格式 → 尝试无密码读取
       a. 无密码能读取 → 普通 ZIP（未加密）→ 加密
       b. 无密码不能读取 → 加密的 ZIP → 尝试用密码解密
    """

    # 步骤 1：不是 zip → 直接加密
    if not is_zip_file(filepath):
        return encrypt_file(filepath, password)

    # 步骤 2：是 zip，尝试无密码读取
    try:
        with pyzipper.AESZipFile(filepath, 'r') as zf:
            for name in zf.namelist():
                zf.read(name)
        # 无密码也能读取 → 普通 zip → 加密
        return encrypt_file(filepath, password)
    except Exception:
        pass  # 无密码读取失败 → 可能是加密的

    # 步骤 3：尝试用密码解密
    return decrypt_file(filepath, password)

# ===== 主程序 =====
def main():
    print("=" * 55)
    print("🔐 ZIP+AES-256 全自动加密/解密")
    print("   拖入即处理，无需选择，自动判断")
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

    ok = fail = 0

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
                    if fp.endswith('.tmp.zip'):
                        continue
                    files.append(fp)

        print(f"\n📂 {os.path.basename(path)} ({len(files)} 个文件)")

        for i, fp in enumerate(files, 1):
            fname = os.path.basename(fp)
            try:
                success, msg = auto_process(fp, password)
                if success:
                    print(f"  [{i}/{len(files)}] {msg} ✅ {fname}")
                    ok += 1
                else:
                    print(f"  [{i}/{len(files)}] ❌ {fname} → {msg}")
                    fail += 1
            except Exception as e:
                print(f"  [{i}/{len(files)}] ❌ {fname} → {e}")
                fail += 1

    print(f"\n{'=' * 55}")
    print(f"🎉 完成！  ✅ {ok} | ❌ {fail}")
    print(f"{'=' * 55}")
    input("回车退出...")

if __name__ == "__main__":
    main()