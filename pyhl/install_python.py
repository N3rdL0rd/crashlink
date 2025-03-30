import urllib3
import os
import subprocess
import platform

CURRENT_PYTHON = "https://www.python.org/ftp/python/3.14.0/Python-3.14.0a6.tar.xz"
DIR = "Python-3.14.0a6"
LIBPYTHON = "libpython3.14.a"
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

def main_nix() -> None:
    print("Downloading Python...")
    download_file(CURRENT_PYTHON, "python.tar.xz")
    print("Extracting...")
    subprocess.run(["tar", "-xf", "python.tar.xz"], check=True)
    print("Configuring...")
    os.chdir(DIR)
    prefix = gen_prefix()
    configure_cmd = f'./configure CFLAGS="-fPIC" --enable-optimizations --with-ensurepip=install --prefix="{prefix}" --disable-test-modules'
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
    # Download the official Python release with dev files
    # We'll use the nuget package instead, which is more reliable for this purpose
    nuget_python_url = "https://www.nuget.org/api/v2/package/python/3.13.0"
    
    print("Downloading Python NuGet package...")
    download_file(nuget_python_url, "python.nupkg")
    
    # Create directories
    prefix = gen_prefix()
    include_dir = os.path.join(INITIAL_DIR, "include")
    if not os.path.exists(include_dir):
        os.makedirs(include_dir)
    
    print("Extracting NuGet package...")
    # NuGet packages are just zip files
    import zipfile
    with zipfile.ZipFile("python.nupkg", 'r') as zip_ref:
        zip_ref.extractall("python_nuget")
    
    print("Copying include files...")
    # The include directory in the NuGet package is at a specific path
    include_src = os.path.join("python_nuget", "tools", "include")
    
    if os.path.exists(include_src):
        print(f"Found include directory at {include_src}")
        # Use os.system to avoid subprocess exceptions with xcopy
        os.system(f'xcopy /E /I /Y "{include_src}" "{include_dir}"')
    else:
        print(f"Include directory not found at {include_src}, searching...")
        # Search for it
        for root, dirs, files in os.walk("python_nuget"):
            if "include" in dirs:
                include_src = os.path.join(root, "include")
                print(f"Found include directory at {include_src}")
                os.system(f'xcopy /E /I /Y "{include_src}" "{include_dir}"')
                break
    
    print("Copying lib files...")
    # Copy the Python lib file from the NuGet package
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
        # Search for Python lib files
        for root, dirs, files in os.walk("python_nuget"):
            python_libs = [f for f in files if f.lower().startswith("python") and f.lower().endswith(".lib")]
            if python_libs:
                lib_src = os.path.join(root, python_libs[0])
                lib_dest = os.path.join(INITIAL_DIR, "python313.lib")
                print(f"Found Python lib at {lib_src}")
                os.system(f'copy /Y "{lib_src}" "{lib_dest}"')
                break
    
    print("Cleaning up...")
    os.remove("python.nupkg")
    import shutil
    shutil.rmtree("python_nuget")
    
    # Verify files were created
    if os.path.exists(include_dir) and os.listdir(include_dir) and os.path.exists(os.path.join(INITIAL_DIR, "python.lib")):
        print("Python setup complete!")
    else:
        print("WARNING: Some files may be missing. Check the include directory and python.lib file.")

if __name__ == "__main__":
    if platform.system() == "Linux":
        main_nix()
    else:
        main_win()
