#!/usr/bin/env python3
# Win32 DLL injector from Grey Hat Python
# Minor formatting cleanups done...
import sys
from ctypes import *
import ctypes
from ctypes.wintypes import LPSTR, LPVOID, HANDLE, DWORD,LPBYTE,LPCSTR


LPCTSTR = ctypes.c_char_p
LPSECURITY_ATTRIBUTES = LPVOID
LPSTARTUPINFO = LPVOID
LPPROCESS_INFORMATION = LPVOID
BOOL = ctypes.c_int

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ('cb', DWORD),
        ('lpReserved', LPSTR),
        ('lpDesktop', LPSTR),
        ('lpTitle', LPSTR),
        ('dwX', DWORD),
        ('dwY', DWORD),
        ('dwXSize', DWORD),
        ('dwYSize', DWORD),
        ('dwXCountChars', DWORD),
        ('dwYCountChars', DWORD),
        ('dwFillAttribute', DWORD),
        ('dwFlags', DWORD),
        ('wShowWindow', DWORD),
        ('cbReserved2', DWORD),
        ('lpReserved2', LPBYTE),
        ('hStdInput', HANDLE),
        ('hStdOutput', HANDLE),
        ('hStdError', HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('hProcess', HANDLE),
        ('hThread', HANDLE),
        ('dwProcessId', DWORD),
        ('dwThreadId', DWORD)
    ]

class ArgObj:
    pid=-1
    exePath=""
    dllPath=""
    def __init__(self,argv):
        curIndex=1
        length=len(argv)
        while curIndex<length:
            if(argv[curIndex]=="-p"):
                self.pid=int(argv[curIndex+1])
                curIndex=curIndex+2
            elif(argv[curIndex]=="-f"):
                self.exePath=argv[curIndex+1]
                curIndex=curIndex+2
            else:
                self.dllPath=argv[curIndex]
                break
kernel32 = windll.kernel32

print("DLL Injector implementation in Python")
print("Taken from Grey Hat Python")


if (len(sys.argv) == 1):
    print("Usage: python3x86 %s [-p pid|-f exe_path] dllpath"%sys.argv[0])
    sys.exit(0)

PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = ( 0x00F0000 | 0x00100000 | 0xFFF )
VIRTUAL_MEM = ( 0x1000 | 0x2000 )

argObj= ArgObj(sys.argv)

h_process=0
dll_path = argObj.dllPath
dll_len = (len(dll_path)+1)*2
if(argObj.pid!=-1):
    pid = argObj.pid
    # Get handle to process being injected...
    h_process = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )

    if not h_process:
        print("[!] Couldn't get handle to PID: %s" %(pid))
        print("[!] Are you sure %s is a valid PID?" %(pid))
        sys.exit(0)
        
else:
    exePath=argObj.exePath
    startInfo= STARTUPINFO()
    startInfo.cb= ctypes.sizeof(STARTUPINFO)
    procInfo= PROCESS_INFORMATION()
    if(not kernel32.CreateProcessW(LPCTSTR(None),exePath,None,None,False,0,None,LPCTSTR(None),ctypes.byref(startInfo),ctypes.byref(procInfo))):
        sys.exit(0)
    h_process=procInfo.hProcess



# Allocate space for DLL path
arg_address = kernel32.VirtualAllocEx(h_process, 0, dll_len, VIRTUAL_MEM, PAGE_READWRITE)

# Write DLL path to allocated space
written = c_int(0)
if(not kernel32.WriteProcessMemory(h_process, arg_address, dll_path, dll_len, byref(written))):
    sys.exit(-1)

# Resolve LoadLibraryA Address
h_kernel32 = kernel32.GetModuleHandleW("KERNEL32.DLL")
h_loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryW")

# Now we createRemoteThread with entrypoiny set to LoadLibraryW and pointer to DLL path as param
thread_id = c_ulong(0)
hThread=kernel32.CreateRemoteThreadEx(h_process, None, 0, h_loadlib, arg_address, 0,None, byref(thread_id))

if(not hThread):
    print("[!] Failed to inject DLL, exit...")
    sys.exit(0)

print ("[+] Remote Thread with ID 0x%08x created."%(thread_id.value))
