// wait, what's the c equivalent of a docstring?

#define HL_NAME(n) pyhl_##n
#include <hl.h>
#include <Python.h>
#include <stdio.h>
#include <libgen.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#define DEBUG true
#define dbg_print(...) do { if (DEBUG) printf("[pyhl] "); printf(__VA_ARGS__); } while(0)

// Global references
static PyObject* g_patch = NULL;
static PyObject* g_hlrun = NULL;
static PyObject* g_argsc = NULL;

HL_PRIM void HL_NAME(init)() {
    if (!Py_IsInitialized()) {
        Py_Initialize();
        
        PyRun_SimpleString("import sys");
        PyRun_SimpleString("sys.path = []");
        PyRun_SimpleString("sys.path.insert(0, '')");
        
        // Get executable path and add to Python path
        char exe_path[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
        if (len != -1) {
            exe_path[len] = '\0';
            char* dir_path = dirname(exe_path);
            
            char py_command[PATH_MAX + 32];
            snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", dir_path);
            PyRun_SimpleString(py_command);
            
            dbg_print("Added binary path to Python sys.path: %s\n", dir_path);

            char bin_lib_py[PATH_MAX];
            snprintf(bin_lib_py, sizeof(bin_lib_py), "%s/lib-py", dir_path);
            snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", bin_lib_py);
            PyRun_SimpleString(py_command);
            dbg_print("Added binary lib-py to Python sys.path: %s\n", bin_lib_py);
            
            // Also add current working directory to Python path
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", cwd);
                PyRun_SimpleString(py_command);
                dbg_print("Added CWD to Python sys.path: %s\n", cwd);
            }
        } else {
            dbg_print("Warning: Could not determine binary path\n");
        }
        
        // Read from /proc/self/cmdline to find input file directory
        FILE* cmdline = fopen("/proc/self/cmdline", "r");
        if (cmdline) {
            char cmd_args[PATH_MAX * 4] = {0};
            size_t bytes_read = fread(cmd_args, 1, sizeof(cmd_args) - 1, cmdline);
            fclose(cmdline);
            
            if (bytes_read > 0) {
                // Find the last argument (likely the input file)
                char* last_arg = NULL;
                char* arg = cmd_args;
                
                while (arg < cmd_args + bytes_read) {
                    if (*arg != '\0') {
                        last_arg = arg;
                        // Move to the end of this argument
                        while (*arg != '\0' && arg < cmd_args + bytes_read) {
                            arg++;
                        }
                    }
                    arg++;
                }
                
                // Process the last argument if found
                if (last_arg && *last_arg) {
                    char* input_path = strdup(last_arg);
                    if (input_path) {
                        char* input_dir = dirname(input_path);
                        if (input_dir) {
                            char py_command[PATH_MAX + 32];
                            snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", input_dir);
                            PyRun_SimpleString(py_command);
                            dbg_print("Added input file directory to Python sys.path: %s\n", input_dir);
                        }
                        free(input_path);
                    }
                }
            }
        } else {
            dbg_print("Warning: Could not read command line arguments\n");
        }

        PyRun_SimpleString("import builtins\n");
        PyRun_SimpleString("builtins.RUNTIME = True\n");
        
        if (DEBUG) {
            PyRun_SimpleString(
                "builtins.DEBUG = True\n"
            );
            PyRun_SimpleString("import __main__\n__main__.DEBUG = True");
            PyRun_SimpleString("print(f'[pyhl] [py] Python DEBUG={DEBUG}')");
            PyRun_SimpleString("print('[pyhl] [py] Python path:', sys.path)");
        }
        
        dbg_print("Looking for patches...\n");
        g_patch = PyImport_ImportModule("crashlink_patch");
        if (g_patch) {
            dbg_print("Successfully imported patch module\n");
            
            // Add to sys.modules to ensure it persists
            PyObject* sys_modules = PyImport_GetModuleDict(); // borrowed reference
            if (sys_modules) {
                PyObject* module_name = PyUnicode_FromString("patch_mod");
                if (module_name) {
                    PyDict_SetItem(sys_modules, module_name, g_patch);
                    Py_DECREF(module_name);
                }
            }
        } else {
            if (PyErr_Occurred()) {
                PyErr_Print();
            }
            dbg_print("Failed to import patch module\n");
        }

        dbg_print("Loading runtime...\n");
        g_hlrun = PyImport_ImportModule("hlrun");
        if (g_hlrun) {
            dbg_print("Successfully imported hlrun module\n");
        } else {
            if (PyErr_Occurred()) {
                PyErr_Print();
            }
            
            PyObject* sys_modules = PyImport_GetModuleDict();
            if (sys_modules) {
                PyObject* module_name = PyUnicode_FromString("hlrun");
                if (module_name) {
                    PyDict_SetItem(sys_modules, module_name, g_hlrun);
                    Py_DECREF(module_name);
                }
            }

            PyRun_SimpleString("import __main__\nfrom hlrun import *\n__main__.hlrun = sys.modules['hlrun']");
            
            g_argsc = PyObject_GetAttrString(g_hlrun, "Args");
            if (!g_argsc) {
                PyErr_Print();
                dbg_print("Warning: Could not find Args class in hlrun\n");
            }

            dbg_print("Failed to import hlrun module\n");
        }
        
        dbg_print("Python %s\n", Py_GetVersion());
    } else {
        dbg_print("Python already loaded\n");
    }
}

HL_PRIM void HL_NAME(deinit)() {
    dbg_print("deinit... ");
    
    // Clean up global references
    Py_XDECREF(g_argsc);
    g_argsc = NULL;
    
    Py_XDECREF(g_patch);
    g_patch = NULL;
    
    if (Py_IsInitialized()) {
        Py_Finalize();
        dbg_print("done!\n");
    }
}

HL_PRIM bool HL_NAME(call)(vbyte* module_utf16, vbyte* name_utf16) {
    dbg_print("call pointers: module=%p, name=%p\n", module_utf16, name_utf16);
    
    // utf16 -> utf8
    char module_utf8[256] = {0};
    char name_utf8[256] = {0};
    int i, j;
    for (i = 0, j = 0; i < 256 && module_utf16[i] != 0; i += 2, j++) {
        module_utf8[j] = module_utf16[i];
    }
    module_utf8[j] = '\0';
    for (i = 0, j = 0; i < 256 && name_utf16[i] != 0; i += 2, j++) {
        name_utf8[j] = name_utf16[i];
    }
    name_utf8[j] = '\0';
    
    dbg_print("converted strings: module='%s', name='%s'\n", module_utf8, name_utf8);
    
    if (!Py_IsInitialized()) {
        HL_NAME(init)();
    }

    dbg_print("loading module...\n");
    PyObject *pName = PyUnicode_FromString(module_utf8);
    if (!pName) {
        PyErr_Print();
        return false;
    }
    
    PyObject *pModule = PyImport_Import(pName);
    Py_DECREF(pName);
    if (!pModule) {
        PyErr_Print();
        return false;
    }
    dbg_print("done!\n");
    
    PyObject *pFunc = PyObject_GetAttrString(pModule, name_utf8);
    if (!pFunc || !PyCallable_Check(pFunc)) {
        PyErr_Print();
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
        return false;
    }
    
    PyObject *pResult = PyObject_CallObject(pFunc, NULL);
    Py_DECREF(pFunc);
    Py_DECREF(pModule);
    
    if (!pResult) {
        PyErr_Print();
        return false;
    }
    
    Py_DECREF(pResult);
    return true;
}

PyObject *hl_to_py(vdynamic* arg, char type) {
    if (!arg) return Py_BuildValue(""); // Py_None with incref
    
    switch (type) {
        case 0: // void (HVOID)
            Py_RETURN_NONE;
        case 1: // u8 (HUI8)
            return PyLong_FromUnsignedLong(arg->v.ui8);
        case 2: // u16 (HUI16)
            return PyLong_FromUnsignedLong(arg->v.ui16);
        case 3: // i32 (HI32)
            return PyLong_FromLong(arg->v.i);
        case 4: // i64 (HI64)
            return PyLong_FromLongLong(arg->v.i64);
        case 5: // f32 (HF32)
            return PyFloat_FromDouble(arg->v.f);
        case 6: // f64 (HF64)
            return PyFloat_FromDouble(arg->v.d);
        case 7: // bool (HBOOL)
            return PyBool_FromLong(arg->v.b);
        case 8: // bytes (HBYTES)
            if (arg->v.bytes)
                return PyBytes_FromString((const char*)arg->v.bytes);
            Py_RETURN_NONE;
        case 9: // dyn (HDYN)
            dbg_print("Warning: Cannot handle dyn type without typing\n");
            Py_RETURN_NONE;
        case 10: // fun (HFUN)
            dbg_print("Warning: HFUN type not implemented\n");
            Py_RETURN_NONE;
        case 11: // obj (HOBJ)
            dbg_print("Warning: HOBJ type not implemented\n");
            Py_RETURN_NONE;
        case 12: // array (HARRAY)
            dbg_print("Warning: HARRAY type not implemented\n");
            Py_RETURN_NONE;
        case 13: // type (HTYPE)
            dbg_print("Warning: HTYPE type not implemented\n");
            Py_RETURN_NONE;
        case 14: // ref (HREF)
            dbg_print("Warning: HREF type not implemented\n");
            Py_RETURN_NONE;
        case 15: // virtual (HVIRTUAL)
            dbg_print("Warning: HVIRTUAL type not implemented\n");
            Py_RETURN_NONE;
        case 16: // dynobj (HDYNOBJ)
            dbg_print("Warning: HDYNOBJ type not implemented\n");
            Py_RETURN_NONE;
        case 17: // abstract (HABSTRACT)
            dbg_print("Warning: HABSTRACT type not implemented\n");
            Py_RETURN_NONE;
        case 18: // enum (HENUM)
            dbg_print("Warning: HENUM type not implemented\n");
            Py_RETURN_NONE;
        case 19: // null (HNULL)
            Py_RETURN_NONE;
        default:
            dbg_print("Warning: Unknown type %d not implemented\n", type);
            Py_RETURN_NONE;
    }
}

HL_PRIM bool HL_NAME(intercept)(vdynamic* args, signed int nargs, vbyte* fn_name_utf16, vbyte* types_utf16) {
    // convert
    char fn_name[256] = {0};
    int i, j;
    for (i = 0, j = 0; i < 256 && fn_name_utf16[i] != 0; i += 2, j++) {
        fn_name[j] = fn_name_utf16[i];
    }
    fn_name[j] = '\0';
    char types[1024] = {0};
    for (i = 0, j = 0; i < 1024 && types_utf16[i] != 0; i += 2, j++) {
        types[j] = types_utf16[i];
    }
    types[j] = '\0';

    // Ensure Python is initialized and pyhl module is loaded
    if (!Py_IsInitialized() || !g_patch) {
        HL_NAME(init)();
    }

    PyObject *pTypes = PyUnicode_FromString(types);
    if (!pTypes) {
        PyErr_Print();
        return false;
    }

    dbg_print("intercept: fn_name='%s', nargs=%d\n", fn_name, nargs);
    unsigned int types_arr[64] = {0};
    int types_count = 0;
    char* token = strtok(types, ",");
    while (token != NULL) {
        types_arr[types_count++] = atoi(token);
        token = strtok(NULL, ",");
    }

    // Check if we have the Args class available
    if (!g_patch || !g_argsc) {
        dbg_print("Error: patch module or Args class not available\n");
        return false;
    }

    PyObject *pName = PyUnicode_FromString(fn_name);
    if (!pName) {
        PyErr_Print();
        return false;
    }

    // Convert HL args to Python objects
    PyObject *pyArgs[64] = {0};
    for (int i = 0; i < nargs; i++) {
        char arg_name[10];
        snprintf(arg_name, sizeof(arg_name), "arg_%d", i);
        vdynamic* arg = hl_dyn_getp(args, hl_hash_utf8(arg_name), &hlt_dyn);
        pyArgs[i] = hl_to_py(arg, types_arr[i]);
    }

    // Create a Python list from the args
    PyObject *pyList = PyList_New(nargs);
    if (!pyList) {
        PyErr_Print();
        for (int i = 0; i < nargs; i++) {
            Py_XDECREF(pyArgs[i]);
        }
        Py_DECREF(pName);
        return false;
    }

    for (int i = 0; i < nargs; i++) {
        // PyList_SetItem steals a reference
        PyList_SetItem(pyList, i, pyArgs[i]);
    }
    
    PyObject *pArgs = PyTuple_New(3);
    PyTuple_SetItem(pArgs, 0, pyList);  // This steals a reference to pyList
    PyTuple_SetItem(pArgs, 1, pName);
    PyTuple_SetItem(pArgs, 2, pTypes);
    
    PyObject *pInstance = PyObject_CallObject(g_argsc, pArgs);
    if (!pInstance) {
        PyErr_Print();
        Py_DECREF(pArgs);
        Py_DECREF(pName);
        return false;
    }
    
    Py_DECREF(pArgs);
    Py_DECREF(pName);

    return true;
}

DEFINE_PRIM(_VOID, init, _NO_ARG);
DEFINE_PRIM(_VOID, deinit, _NO_ARG);
DEFINE_PRIM(_BOOL, call, _BYTES _BYTES);
DEFINE_PRIM(_BOOL, intercept, _DYN _I32 _BYTES _BYTES);