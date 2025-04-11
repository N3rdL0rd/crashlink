// wait, what's the c equivalent of a docstring?

#define HL_NAME(n) pyhl_##n
#include <hl.h>
#include <Python.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

// Platform-specific includes
#ifdef _WIN32
#include <Windows.h>
#include <direct.h>  // for _getcwd

#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif

#define getcwd _getcwd
#else
#include <libgen.h>
#include <unistd.h>
#endif

//////////
#define DEBUG true
//////////

#define dbg_print(...)           \
    do                           \
    {                            \
        if (DEBUG)               \
        {                            \
            printf("[pyhl] ");   \
            printf(__VA_ARGS__); \
        }                        \
    } while (0)

#define err(...)                         \
    do                                   \
    {                                    \
        printf("\033[31m[pyhl ERROR] "); \
        printf(__VA_ARGS__);             \
        printf("\033[0m");               \
    } while (0)

#define warn(...)                          \
    do                                     \
    {                                      \
        printf("\033[33m[pyhl WARNING] "); \
        printf(__VA_ARGS__);               \
        printf("\033[0m");                 \
    } while (0)

// Helper function to extract directory from path on Windows
#ifdef _WIN32
char* dirname(char* path) {
    static char dir[PATH_MAX];
    strncpy(dir, path, PATH_MAX);
    
    // Find last separator
    char* last_sep = strrchr(dir, '\\');
    if (!last_sep) {
        last_sep = strrchr(dir, '/');
    }
    
    if (last_sep) {
        *last_sep = '\0';  // Truncate at separator
        return dir;
    } else {
        // No separator found, return "."
        strcpy(dir, ".");
        return dir;
    }
}
#endif

// Global references
static PyObject *g_patchc = NULL;
static PyObject *g_hlrun = NULL;
static PyObject *g_argsc = NULL;

HL_PRIM void HL_NAME(init)()
{
    if (!Py_IsInitialized())
    {
        Py_Initialize();

        PyRun_SimpleString("import sys");
        PyRun_SimpleString("sys.path = []");
        PyRun_SimpleString("sys.path.insert(0, '')");

        // get executable path and add to Python path
        char exe_path[PATH_MAX];
        
        #ifdef _WIN32
        // Windows: use GetModuleFileName to get executable path
        if (GetModuleFileNameA(NULL, exe_path, PATH_MAX) > 0)
        {
        #else
        // Unix: use readlink on /proc/self/exe
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
        if (len != -1)
        {
            exe_path[len] = '\0';
        #endif
            char *dir_path = dirname(exe_path);

            char py_command[PATH_MAX + 32];
            snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", dir_path);
            PyRun_SimpleString(py_command);

            dbg_print("Added binary path to Python sys.path: %s\n", dir_path);

            char bin_lib_py[PATH_MAX];
            #ifdef _WIN32
            snprintf(bin_lib_py, sizeof(bin_lib_py), "%s\\lib-py", dir_path);
            #else
            snprintf(bin_lib_py, sizeof(bin_lib_py), "%s/lib-py", dir_path);
            #endif
            snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", bin_lib_py);
            PyRun_SimpleString(py_command);
            dbg_print("Added binary lib-py to Python sys.path: %s\n", bin_lib_py);

            // also add current working directory to Python path
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL)
            {
                snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", cwd);
                PyRun_SimpleString(py_command);
                dbg_print("Added CWD to Python sys.path: %s\n", cwd);
            }
        }
        else
        {
            warn("Could not determine binary path\n");
        }

        // read command line arguments
        #ifdef _WIN32
        // Windows: use GetCommandLineA and parse it
        char cmd_args[PATH_MAX * 4] = {0};
        strncpy(cmd_args, GetCommandLineA(), sizeof(cmd_args) - 1);
        
        // Simple command line parsing - find last argument
        char *last_arg = NULL;
        char *arg = cmd_args;
        bool in_quotes = false;
        
        while (*arg) {
            // Skip leading whitespace
            while (*arg == ' ' || *arg == '\t') arg++;
            
            // Mark start of this argument
            char *start = arg;
            
            // Handle quoted arguments
            if (*arg == '"') {
                in_quotes = true;
                start++; // Skip the quote
                arg++;
                
                // Find end of quoted section
                while (*arg && (*arg != '"' || in_quotes)) {
                    if (*arg == '"') in_quotes = false;
                    arg++;
                }
                
                if (*arg == '"') *arg++ = '\0'; // Replace closing quote with null
            } else {
                // Find end of non-quoted argument
                while (*arg && *arg != ' ' && *arg != '\t') arg++;
                
                if (*arg) *arg++ = '\0';
            }
            
            if (*start) last_arg = start;
        }
        
        #else
        // Unix: read from /proc/self/cmdline
        FILE *cmdline = fopen("/proc/self/cmdline", "r");
        if (cmdline)
        {
            char cmd_args[PATH_MAX * 4] = {0};
            size_t bytes_read = fread(cmd_args, 1, sizeof(cmd_args) - 1, cmdline);
            fclose(cmdline);

            if (bytes_read > 0)
            {
                char *last_arg = NULL;
                char *arg = cmd_args;

                while (arg < cmd_args + bytes_read)
                {
                    if (*arg != '\0')
                    {
                        last_arg = arg;
                        // Move to the end of this argument
                        while (*arg != '\0' && arg < cmd_args + bytes_read)
                        {
                            arg++;
                        }
                    }
                    arg++;
                }
        #endif
                
                if (last_arg && *last_arg)
                {
                    #ifdef _WIN32
                    char *input_path = _strdup(last_arg);
                    #else
                    char *input_path = strdup(last_arg);
                    #endif
                    
                    if (input_path)
                    {
                        char *input_dir = dirname(input_path);
                        if (input_dir)
                        {
                            char py_command[PATH_MAX + 32];
                            snprintf(py_command, sizeof(py_command), "sys.path.insert(0, '%s')", input_dir);
                            PyRun_SimpleString(py_command);
                            dbg_print("Added input file directory to Python sys.path: %s\n", input_dir);
                        }
                        free(input_path);
                    }
                }
        #ifndef _WIN32
            }
        }
        else
        {
            warn("Could not read command line arguments\n");
        }
        #endif

        PyRun_SimpleString("import builtins\n");
        PyRun_SimpleString("builtins.RUNTIME = True\n");

        if (DEBUG)
        {
            PyRun_SimpleString(
                "builtins.DEBUG = True\n");
            PyRun_SimpleString("import __main__\n__main__.DEBUG = True");
            PyRun_SimpleString("print(f'[pyhl] [py] Python DEBUG={DEBUG}')");
            PyRun_SimpleString("print('[pyhl] [py] Python path:', sys.path)");
        }

        dbg_print("Looking for patches...\n");
        PyObject *patchMod = PyImport_ImportModule("crashlink_patch");
        if (patchMod)
        {
            dbg_print("Successfully imported patch module\n");

            // add to sys.modules to ensure it persists
            PyObject *sys_modules = PyImport_GetModuleDict(); // borrowed reference
            if (sys_modules)
            {
                PyObject *module_name = PyUnicode_FromString("patch_mod");
                if (module_name)
                {
                    PyDict_SetItem(sys_modules, module_name, patchMod);
                    Py_DECREF(module_name);
                }
            }

            g_patchc = PyObject_GetAttrString(patchMod, "patch");
            if (!g_patchc)
            {
                PyErr_Print();
                err("Could not find patch instance in patch module\n");
                exit(1);
            }
        }
        else
        {
            if (PyErr_Occurred())
            {
                PyErr_Print();
            }
            err("Failed to import patch module\n");
            exit(1);
        }

        dbg_print("Loading runtime...\n");
        g_hlrun = PyImport_ImportModule("hlrun");
        if (g_hlrun)
        {
            dbg_print("Successfully imported hlrun module\n");

            g_argsc = PyObject_GetAttrString(g_hlrun, "Args");
            if (!g_argsc)
            {
                PyErr_Print();
                err("Could not find Args class in hlrun\n");
                exit(1);
            }
        }
        else
        {
            if (PyErr_Occurred())
            {
                PyErr_Print();
            }

            PyObject *sys_modules = PyImport_GetModuleDict();
            if (sys_modules)
            {
                PyObject *module_name = PyUnicode_FromString("hlrun");
                if (module_name)
                {
                    PyDict_SetItem(sys_modules, module_name, g_hlrun);
                    Py_DECREF(module_name);
                }
            }

            PyRun_SimpleString("import __main__\nfrom hlrun import *\n__main__.hlrun = sys.modules['hlrun']");

            err("Failed to import hlrun module\n");
            err("Couldn't import hlrun!\n");
            exit(1);
        }

        dbg_print("Python %s\n", Py_GetVersion());
    }
    else
    {
        warn("Python already loaded\n");
    }
}

HL_PRIM void HL_NAME(deinit)()
{
    dbg_print("deinit... ");

    Py_XDECREF(g_argsc);
    g_argsc = NULL;

    Py_XDECREF(g_patchc);
    g_patchc = NULL;

    if (Py_IsInitialized())
    {
        Py_Finalize();
        dbg_print("done!\n");
    }
}

HL_PRIM bool HL_NAME(call)(vbyte *module_utf16, vbyte *name_utf16)
{
    dbg_print("call pointers: module=%p, name=%p\n", module_utf16, name_utf16);

    // utf16 -> utf8
    char module_utf8[256] = {0};
    char name_utf8[256] = {0};
    int i, j;
    for (i = 0, j = 0; i < 256 && module_utf16[i] != 0; i += 2, j++)
    {
        module_utf8[j] = module_utf16[i];
    }
    module_utf8[j] = '\0';
    for (i = 0, j = 0; i < 256 && name_utf16[i] != 0; i += 2, j++)
    {
        name_utf8[j] = name_utf16[i];
    }
    name_utf8[j] = '\0';

    dbg_print("converted strings: module='%s', name='%s'\n", module_utf8, name_utf8);

    if (!Py_IsInitialized())
    {
        HL_NAME(init)();
    }

    dbg_print("loading module...\n");
    PyObject *pName = PyUnicode_FromString(module_utf8);
    if (!pName)
    {
        PyErr_Print();
        return false;
    }

    PyObject *pModule = PyImport_Import(pName);
    Py_DECREF(pName);
    if (!pModule)
    {
        PyErr_Print();
        return false;
    }
    dbg_print("done!\n");

    PyObject *pFunc = PyObject_GetAttrString(pModule, name_utf8);
    if (!pFunc || !PyCallable_Check(pFunc))
    {
        PyErr_Print();
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
        return false;
    }

    PyObject *pResult = PyObject_CallObject(pFunc, NULL);
    Py_DECREF(pFunc);
    Py_DECREF(pModule);

    if (!pResult)
    {
        PyErr_Print();
        return false;
    }

    Py_DECREF(pResult);
    return true;
}

PyObject *hl_to_py(vdynamic *arg, char type)
{
    if (!arg)
        return Py_BuildValue(""); // Py_None with incref

    switch (type)
    {
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
            return PyBytes_FromString((const char *)arg->v.bytes);
        Py_RETURN_NONE;
    case 9: // dyn (HDYN)
        warn("Cannot handle dyn type without typing\n");
        Py_RETURN_NONE;
    case 10: // fun (HFUN)
        warn("HFUN type not implemented\n");
        Py_RETURN_NONE;
    case 11: // obj (HOBJ)
        warn("HOBJ type not implemented\n");
        Py_RETURN_NONE;
    case 12: // array (HARRAY)
        warn("HARRAY type not implemented\n");
        Py_RETURN_NONE;
    case 13: // type (HTYPE)
        warn("HTYPE type not implemented\n");
        Py_RETURN_NONE;
    case 14: // ref (HREF)
        warn("HREF type not implemented\n");
        Py_RETURN_NONE;
    case 15: // virtual (HVIRTUAL)
        warn("HVIRTUAL type not implemented\n");
        Py_RETURN_NONE;
    case 16: // dynobj (HDYNOBJ)
        warn("HDYNOBJ type not implemented\n");
        Py_RETURN_NONE;
    case 17: // abstract (HABSTRACT)
        warn("HABSTRACT type not implemented\n");
        Py_RETURN_NONE;
    case 18: // enum (HENUM)
        warn("HENUM type not implemented\n");
        Py_RETURN_NONE;
    case 19: // null (HNULL)
        Py_RETURN_NONE;
    default:
        warn("Unknown type %d not implemented\n", type);
        Py_RETURN_NONE;
    }
}

vdynamic *py_to_hl(PyObject *arg, char type)
{
    if (!arg || arg == Py_None)
        return NULL;

    vdynamic *result = NULL;

    switch (type)
    {
    case 0: // void (HVOID)
        return NULL;
    case 1: // u8 (HUI8)
        warn("Can't handle U8. Whoops!\n");
        break;
    case 2: // u16 (HUI16)
        warn("Can't handle U16. Whoops!\n");
        break;
    case 3: // i32 (HI32)
        warn("Can't handle I32. Whoops!\n");
        break;
    case 4: // i64 (HI64)
        if (PyLong_Check(arg))
        {
            result = hl_alloc_dynamic(&hlt_i64);
            result->v.i64 = PyLong_AsLongLong(arg);
            if (PyErr_Occurred())
            {
                PyErr_Print();
                return NULL;
            }
        }
        break;
    case 5: // f32 (HF32)
        if (PyFloat_Check(arg))
        {
            result = hl_alloc_dynamic(&hlt_f32);
            result->v.f = (float)PyFloat_AsDouble(arg);
            if (PyErr_Occurred())
            {
                PyErr_Print();
                return NULL;
            }
        }
        break;
    case 6: // f64 (HF64)
        if (PyFloat_Check(arg))
        {
            result = hl_alloc_dynamic(&hlt_f64);
            result->v.d = PyFloat_AsDouble(arg);
            if (PyErr_Occurred())
            {
                PyErr_Print();
                return NULL;
            }
        }
        break;
    case 7: // bool (HBOOL)
        if (PyBool_Check(arg))
        {
            result = hl_alloc_dynamic(&hlt_bool);
            result->v.b = (arg == Py_True);
        }
        break;
    case 8: // bytes (HBYTES)
        if (PyBytes_Check(arg))
        {
            Py_ssize_t size;
            char *bytes;
            if (PyBytes_AsStringAndSize(arg, &bytes, &size) != -1)
            {
                vbyte *hl_bytes = hl_copy_bytes((vbyte *)bytes, size);
                if (hl_bytes)
                {
                    result = hl_alloc_dynamic(&hlt_bytes);
                    result->v.bytes = hl_bytes;
                }
            }
        }
        break;
    case 9: // dyn (HDYN)
        warn("Cannot handle dyn type without typing in py_to_hl\n");
        break;
    case 10: // fun (HFUN)
        warn("HFUN type not implemented in py_to_hl\n");
        break;
    case 11: // obj (HOBJ)
        warn("HOBJ type not implemented in py_to_hl\n");
        break;
    case 12: // array (HARRAY)
        warn("HARRAY type not implemented in py_to_hl\n");
        break;
    case 13: // type (HTYPE)
        warn("HTYPE type not implemented in py_to_hl\n");
        break;
    case 14: // ref (HREF)
        warn("HREF type not implemented in py_to_hl\n");
        break;
    case 15: // virtual (HVIRTUAL)
        warn("HVIRTUAL type not implemented in py_to_hl\n");
        break;
    case 16: // dynobj (HDYNOBJ)
        warn("HDYNOBJ type not implemented in py_to_hl\n");
        break;
    case 17: // abstract (HABSTRACT)
        warn("HABSTRACT type not implemented in py_to_hl\n");
        break;
    case 18: // enum (HENUM)
        warn("HENUM type not implemented in py_to_hl\n");
        break;
    case 19: // null (HNULL)
        return NULL;
    default:
        warn("Unknown type %d not implemented in py_to_hl\n", type);
        break;
    }

    if (!result)
    {
        dbg_print("Failed to convert Python object to HL type %d\n", type);
    }

    return result;
}

HL_PRIM bool HL_NAME(intercept)(vdynamic *args, signed int nargs, vbyte *fn_name_utf16, vbyte *types_utf16)
{
    if (!g_argsc)
    {
        err("Args class not available\n");
        return false;
    }

    // convert
    char fn_name[256] = {0};
    int i, j;
    for (i = 0, j = 0; i < 256 && fn_name_utf16[i] != 0; i += 2, j++)
    {
        fn_name[j] = fn_name_utf16[i];
    }
    fn_name[j] = '\0';
    char types[1024] = {0};
    for (i = 0, j = 0; i < 1024 && types_utf16[i] != 0; i += 2, j++)
    {
        types[j] = types_utf16[i];
    }
    types[j] = '\0';

    if (!Py_IsInitialized() || !g_patchc)
    {
        HL_NAME(init)();
    }

    PyObject *pTypes = PyUnicode_FromString(types);
    if (!pTypes)
    {
        PyErr_Print();
        return false;
    }

    dbg_print("intercept: fn_name='%s', nargs=%d\n", fn_name, nargs);
    unsigned int types_arr[64] = {0};
    int types_count = 0;
    char *token = strtok(types, ",");
    while (token != NULL)
    {
        types_arr[types_count++] = atoi(token);
        token = strtok(NULL, ",");
    }

    PyObject *pName = PyUnicode_FromString(fn_name);
    if (!pName)
    {
        PyErr_Print();
        return false;
    }

    PyObject *pyArgs[64] = {0};
    for (int i = 0; i < nargs; i++)
    {
        char arg_name[10];
        snprintf(arg_name, sizeof(arg_name), "arg_%d", i);
        vdynamic *arg = hl_dyn_getp(args, hl_hash_utf8(arg_name), &hlt_dyn);
        pyArgs[i] = hl_to_py(arg, types_arr[i]);
    }

    PyObject *pyList = PyList_New(nargs);
    if (!pyList)
    {
        PyErr_Print();
        for (int i = 0; i < nargs; i++)
        {
            Py_XDECREF(pyArgs[i]);
        }
        Py_DECREF(pName);
        return false;
    }

    for (int i = 0; i < nargs; i++)
    {
        PyList_SetItem(pyList, i, pyArgs[i]);
    }

    PyObject *pArgs = PyTuple_New(3);
    PyTuple_SetItem(pArgs, 0, pyList);
    PyTuple_SetItem(pArgs, 1, pName);
    PyTuple_SetItem(pArgs, 2, pTypes);

    PyObject *pInstance = PyObject_CallObject(g_argsc, pArgs);
    if (!pInstance)
    {
        PyErr_Print();
        Py_DECREF(pArgs);
        Py_DECREF(pName);
        return false;
    }

    PyObject *pInterceptArgs = PyTuple_New(2);
    PyTuple_SetItem(pInterceptArgs, 0, pInstance);
    PyTuple_SetItem(pInterceptArgs, 1, pName);
    PyObject *pNewArgs = PyObject_CallObject(PyObject_GetAttrString(g_patchc, "do_intercept"), pInterceptArgs);
    if (!pNewArgs)
    {
        PyErr_Print();
        Py_DECREF(pArgs);
        Py_DECREF(pName);
        Py_DECREF(pInterceptArgs);
        return false;
    }
    PyObject *pNewArgsHl = PyObject_CallObject(PyObject_GetAttrString(pNewArgs, "to_hl"), NULL);
    if (!pNewArgsHl)
    {
        PyErr_Print();
        Py_DECREF(pArgs);
        Py_DECREF(pName);
        Py_DECREF(pInterceptArgs);
        Py_DECREF(pNewArgs);
        return false;
    }

    // now, pNewArgsHl is of type List[Any], and we can convert each type back to hl
    for (int i = 0; i < nargs; i++)
    {
        char arg_name[15];
        snprintf(arg_name, sizeof(arg_name), "arg_%d", i);

        // create py int for the index
        PyObject *pIndex = PyLong_FromLong(i);
        if (!pIndex)
        {
            PyErr_Print();
            continue;
        }

        PyObject *pItem = PyObject_GetItem(pNewArgsHl, pIndex);
        Py_DECREF(pIndex);

        if (!pItem)
        {
            PyErr_Print();
            continue;
        }

        vdynamic *argPy = py_to_hl(pItem, types_arr[i]);
        Py_DECREF(pItem);

        if (argPy)
        {
            hl_dyn_setp(args, hl_hash_utf8(arg_name), &hlt_dyn, argPy);
        }
    }

    Py_DECREF(pArgs);
    Py_DECREF(pName);
    Py_DECREF(pInterceptArgs);
    Py_DECREF(pNewArgs);

    return true;
}

DEFINE_PRIM(_VOID, init, _NO_ARG);
DEFINE_PRIM(_VOID, deinit, _NO_ARG);
DEFINE_PRIM(_BOOL, call, _BYTES _BYTES);
DEFINE_PRIM(_BOOL, intercept, _DYN _I32 _BYTES _BYTES);