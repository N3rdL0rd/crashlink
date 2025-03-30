import urllib3
import os
import subprocess

CURRENT_PYTHON = "https://www.python.org/ftp/python/3.14.0/Python-3.14.0a6.tar.xz"
DIR = "Python-3.14.0a6"
INITIAL_DIR = os.getcwd()

def download_file(url: str, dest: str) -> None:
    """
    Download a file from a URL to a local destination.
    """
    http = urllib3.PoolManager()
    response = http.request('GET', url, preload_content=False)
    if response.status != 200:
        raise RuntimeError(f"Failed to download file: {response.status}")

    with open(dest, 'wb') as out_file:
        while True:
            data = response.read(1024)
            if not data:
                break
            out_file.write(data)

    response.release_conn()

def gen_prefix() -> str:
    """
    Generate a prefix for the installation directory.
    """
    prefix = os.path.join(INITIAL_DIR, "python")
    if not os.path.exists(prefix):
        os.makedirs(prefix)
    return prefix

def main() -> None:
    print("Downloading Python...")
    download_file(CURRENT_PYTHON, "python.tar.xz")
    print("Extracting...")
    subprocess.run(["tar", "-xf", "python.tar.xz"], check=True)
    print("Configuring...")
    os.chdir(DIR)
    prefix = gen_prefix()
    configure_cmd = f'./configure --enable-optimizations --with-ensurepip=install --prefix="{prefix}" --disable-test-modules'
    subprocess.run(configure_cmd, shell=True, check=True)
    print("Building...")
    subprocess.run("make -j$(($(nproc) + 1))", shell=True, check=True)
    print("Installing...")
    subprocess.run("make install", shell=True, check=True)
    print("Cleaning up...")
    os.chdir(INITIAL_DIR)
    subprocess.run(["rm", "-rf", DIR], check=True)
    subprocess.run(["rm", "python.tar.xz"], check=True)
    print("Python built!")

if __name__ == "__main__":
    main()