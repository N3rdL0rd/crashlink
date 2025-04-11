import os
import platform
import shutil
import subprocess
import zipfile

import requests

CURRENT_PYTHON = "https://www.python.org/ftp/python/3.14.0/Python-3.14.0a6.tar.xz"
DIR = "Python-3.14.0a6"
LIBPYTHON = "libpython3.14.a"
INITIAL_DIR = os.getcwd()


def download_file(url: str, dest: str) -> None:
    """
    Download a file from a URL to a local destination using urllib.request.
    """
    print(f"Downloading {url} to {dest}...")
    r = requests.get(url)
    with open(dest, "wb") as f:
        f.write(r.content)


def gen_prefix() -> str:
    """
    Generate a prefix for the installation directory.
    """
    prefix = os.path.join(INITIAL_DIR, "python")
    if not os.path.exists(prefix):
        os.makedirs(prefix)
    return prefix


def check_libffi() -> bool:
    """
    Check if the libffi development package is installed by using pkg-config.
    If not found, print instructions based on the detected Linux distro.
    """
    print("Checking for libffi development package...")
    try:
        subprocess.run(["pkg-config", "--exists", "libffi"], check=True)
        print("libffi found.")
        return True
    except subprocess.CalledProcessError:
        print("libffi not found.")
        distro_id = "unknown"
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                content = f.read().lower()
                if "fedora" in content or "red hat" in content or "centos" in content:
                    distro_id = "fedora"
                elif "ubuntu" in content or "debian" in content:
                    distro_id = "debian"
        if distro_id == "fedora":
            print("Please install libffi-devel via: sudo dnf install libffi-devel")
        elif distro_id == "debian":
            print("Please install libffi-dev via: sudo apt-get install libffi-dev")
        else:
            print("Please install the libffi development package for your distribution.")
        return False


def main_nix() -> None:
    if not check_libffi():
        print("Missing libffi. Cannot proceed with Python build.")
        exit(1)
    print("Downloading Python...")
    download_file(CURRENT_PYTHON, "python.tar.xz")
    print("Extracting...")
    subprocess.run(["tar", "-xf", "python.tar.xz"], check=True)
    print("Configuring...")
    os.chdir(DIR)
    prefix = gen_prefix()
    configure_cmd = f'./configure CFLAGS="-fPIC" --with-ensurepip=install --prefix="{prefix}" --disable-test-modules'
    subprocess.run(configure_cmd, shell=True, check=True)
    print("Building...")
    subprocess.run("make -j$(($(nproc) + 1))", shell=True, check=True)
    print("Installing...")
    subprocess.run("make install", shell=True, check=True)
    print("Cleaning up...")
    os.chdir(INITIAL_DIR)
    subprocess.run(["rm", "-rf", DIR], check=True)
    subprocess.run(["rm", "python.tar.xz"], check=True)
    print("Copying libpython...")
    os.system("cp python/lib/libpython3.14.a libpython.a")
    print("Copying include...")
    os.system("cp -r python/include/python* include")
    print("Python built!")


def main_win() -> None:
    nuget_python_url = "https://www.nuget.org/api/v2/package/python/3.13.0"

    print("Downloading Python NuGet package...")
    download_file(nuget_python_url, "python.nupkg")

    prefix = gen_prefix()
    include_dir = os.path.join(INITIAL_DIR, "include")
    if not os.path.exists(include_dir):
        os.makedirs(include_dir)

    print("Extracting NuGet package...")
    # NuGet packages are just zip files

    with zipfile.ZipFile("python.nupkg", "r") as zip_ref:
        zip_ref.extractall("python_nuget")

    print("Copying include files...")
    include_src = os.path.join("python_nuget", "tools", "include")

    if os.path.exists(include_src):
        print(f"Found include directory at {include_src}")
        # Use os.system to avoid subprocess exceptions with xcopy
        os.system(f'xcopy /E /I /Y "{include_src}" "{include_dir}"')
    else:
        print(f"Include directory not found at {include_src}, searching...")
        for root, dirs, files in os.walk("python_nuget"):
            if "include" in dirs:
                include_src = os.path.join(root, "include")
                print(f"Found include directory at {include_src}")
                os.system(f'xcopy /E /I /Y "{include_src}" "{include_dir}"')
                break

    print("Copying lib files...")
    lib_src_dir = os.path.join("python_nuget", "tools", "libs")

    if os.path.exists(lib_src_dir):
        for file in os.listdir(lib_src_dir):
            if file.lower().startswith("python") and file.lower().endswith(".lib"):
                lib_src = os.path.join(lib_src_dir, file)
                lib_dest = os.path.join(INITIAL_DIR, "python313.lib")
                print(f"Copying {lib_src} to {lib_dest}")
                os.system(f'copy /Y "{lib_src}" "{lib_dest}"')
                break
    else:
        print(f"Lib directory not found at {lib_src_dir}, searching...")
        for root, dirs, files in os.walk("python_nuget"):
            python_libs = [f for f in files if f.lower().startswith("python") and f.lower().endswith(".lib")]
            if python_libs:
                lib_src = os.path.join(root, python_libs[0])
                lib_dest = os.path.join(INITIAL_DIR, "python313.lib")
                print(f"Found Python lib at {lib_src}")
                os.system(f'copy /Y "{lib_src}" "{lib_dest}"')
                break
            
    os.system(f"copy /Y python_nuget\\tools\\python313.dll ")
    
    print("Copying Lib...")
    lib_src = os.path.join("python_nuget", "tools", "Lib")
    lib_dest = "lib-py"
    if os.path.exists(lib_src):
        print(f"Found Lib directory at {lib_src}")
        os.system(f'xcopy /E /I /Y "{lib_src}" "{lib_dest}"')
    else:
        print(f"Lib directory not found at {lib_src}, searching...")
        for root, dirs, files in os.walk("python_nuget"):
            if "Lib" in dirs:
                lib_src = os.path.join(root, "Lib")
                print(f"Found Lib directory at {lib_src}")
                os.system(f'xcopy /E /I /Y "{lib_src}" "{lib_dest}"')
                break

    print("Cleaning up...")
    os.remove("python.nupkg")

    shutil.rmtree("python_nuget")
    shutil.rmtree("python", ignore_errors=True)

    if (
        os.path.exists(include_dir)
        and os.listdir(include_dir)
        and os.path.exists(os.path.join(INITIAL_DIR, "python.lib"))
    ):
        print("Python setup complete!")
    else:
        print("WARNING: Some files may be missing. Check the include directory and python.lib file.")


if __name__ == "__main__":
    if platform.system() == "Linux":
        main_nix()
    else:
        main_win()
