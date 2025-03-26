#define HL_NAME(n) pyhl_##n
#include <hl.h>
#include <Python.h>
#include <stdio.h>

#define DEBUG true
#define dbg_print(...) do { if (DEBUG) printf(__VA_ARGS__); } while(0)

HL_PRIM void HL_NAME(init)() {
    dbg_print("[pyhl] init...");
    if (!Py_IsInitialized()) {
        Py_Initialize();
        dbg_print(" done...\n");
        PyRun_SimpleString("print('[pyhl] Hello from Python!')");
    } else {
        dbg_print(" already loaded\n");
    }
}

HL_PRIM void HL_NAME(deinit)() {
    dbg_print("[pyhl] deinit... ");
    if (Py_IsInitialized()) {
        Py_Finalize();
        dbg_print("done!\n");
    }
}

HL_PRIM bool HL_NAME(call)(vbyte* module_utf16, vbyte* name_utf16) {
    dbg_print("[pyhl] call pointers: module=%p, name=%p\n", module_utf16, name_utf16);
    
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
    
    dbg_print("[pyhl] converted strings: module='%s', name='%s'\n", module_utf8, name_utf8);
    
    if (!Py_IsInitialized()) {
        Py_Initialize();
    }

    dbg_print("[pyhl] loading module...\n");
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
    dbg_print("[pyhl] done!\n");
    
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

    return true;
}

HL_PRIM bool HL_NAME(intercept)(vdynamic* args, signed char nargs, vbyte* fn_name_utf16) {
    // convert
    char fn_name[256] = {0};
    int i, j;
    for (i = 0, j = 0; i < 256 && fn_name[i] != 0; i += 2, j++) {
        fn_name[j] = fn_name[i];
    }
    fn_name[j] = '\0';

}

DEFINE_PRIM(_VOID, init, _NO_ARG);
DEFINE_PRIM(_VOID, deinit, _NO_ARG);
DEFINE_PRIM(_BOOL, call, _BYTES _BYTES);