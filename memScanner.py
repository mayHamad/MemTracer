import argparse
import os
import sys
from ctypes import *
from ctypes.wintypes import *
import win32process
import win32api
import pywintypes
import json
from collections import OrderedDict

peHeader =[ 0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65 ]
        
MEMORY_STATES = {0x1000: "MEM_COMMIT", 0x10000: "MEM_FREE", 0x2000: "MEM_RESERVE"}
MEMORY_PROTECTIONS = {0x10: "EXECUTE", 0x20: "EXECUTE_READ", 0x40: "EXECUTE_READWRITE", 0x80: "EXECUTE_WRITECOPY", 0x01: "NOACCESS", 0x04: "READWRITE", 0x08: "WRITECOPY", 0x02: "READONLY"}
MEMORY_TYPES = {0x1000000: "MEM_IMAGE", 0x40000: "MEM_MAPPED", 0x20000: "MEM_PRIVATE"}
PROCESS_QUERY_INFORMATION = 0x0400;
PROCESS_WM_READ = 0x0010

class MEMORY_BASIC_INFORMATION32 (Structure):
    _fields_ = [
        ("BaseAddress", c_void_p),
        ("AllocationBase", c_void_p),
        ("AllocationProtect", DWORD),
        ("RegionSize", c_size_t),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD)
        ]

class MEMORY_BASIC_INFORMATION64 (Structure):
    _fields_ = [
        ("BaseAddress", c_ulonglong),
        ("AllocationBase", c_ulonglong),
        ("AllocationProtect", DWORD),
        ("__alignment1", DWORD),
        ("RegionSize", c_ulonglong),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ("__alignment2", DWORD)
        ]

class SYSTEM_INFO(Structure):

    _fields_ = [("wProcessorArchitecture", WORD),
                ("wReserved", WORD),
                ("dwPageSize", DWORD),
                ("lpMinimumApplicationAddress", LPVOID),
                ("lpMaximumApplicationAddress", LPVOID),
                ("dwActiveProcessorMask", DWORD),
                ("dwNumberOfProcessors", DWORD),
                ("dwProcessorType", DWORD),
                ("dwAllocationGranularity", DWORD),
                ("wProcessorLevel", WORD),
                ("wProcessorRevision", WORD)]

class MEMORY_BASIC_INFORMATION:

    def __init__ (self, MBI):
        self.MBI = MBI
        self.set_attributes()

    def set_attributes(self):
        self.BaseAddress = self.MBI.BaseAddress
        self.AllocationBase = self.MBI.AllocationBase
        self.AllocationProtect = MEMORY_PROTECTIONS.get(self.MBI.AllocationProtect, self.MBI.AllocationProtect)
        self.RegionSize = self.MBI.RegionSize
        self.State = MEMORY_STATES.get(self.MBI.State, self.MBI.State)
        self.Protect = MEMORY_PROTECTIONS.get(self.MBI.Protect, self.MBI.Protect)
        self.Type = MEMORY_TYPES.get(self.MBI.Type, self.MBI.Type)
        self.ProtectBits = self.MBI.Protect

def ModuleScan(ModuleName):
    mLst = []
    pids = win32process.EnumProcesses()
    for pid in pids:
        if pid == 0:
            continue
        try:
            hProc = win32api.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, False, pid)
            ProcName = win32process.GetModuleFileNameEx(hProc, 0)
            ProcPath, ProcName = os.path.split(ProcName)
            modlist = win32process.EnumProcessModules(hProc)
            for i in modlist:
                Mname = win32process.GetModuleFileNameEx(hProc, i)
                Mpath, Mname = os.path.split(Mname)
                if (Mname == ModuleName):
                    record = OrderedDict([
                        ("Process Name", ProcName),
                        ("PID:",pid),
                        ("Process Path", ProcPath),
                        ("Module Path", Mpath),
                        ("Module Name", Mname)
                    ])
                    mLst.append(u"{}".format(json.dumps(record)))  
        except pywintypes.error as err:
            #print (str(err))
            continue
    return mLst
    
def ReflectiveScan():
    dLst = []
    si = SYSTEM_INFO()
    psi = byref(si)
    windll.kernel32.GetSystemInfo(psi)
    min_address = si.lpMinimumApplicationAddress
    max_address = si.lpMaximumApplicationAddress
    lpBuffer = MEMORY_BASIC_INFORMATION64()
    pids = win32process.EnumProcesses()
    for pid in pids:
        if pid == 0:
            continue
        try:
            ProcHandle = win32api.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, False, pid)
            ProcName = win32process.GetModuleFileNameEx(ProcHandle, 0)
            ProcPath, ProcName = os.path.split(ProcName)
            base_address = min_address
            while base_address < max_address:
                windll.kernel32.VirtualQueryEx(ProcHandle.handle, LPVOID(base_address), ctypes.byref(lpBuffer), ctypes.sizeof(lpBuffer))
                info = MEMORY_BASIC_INFORMATION(lpBuffer)
                if (((info.Protect == "EXECUTE_READWRITE") or (info.Protect == "EXECUTE_READ") or (info.Protect == "READWRITE")) and info.State == "MEM_COMMIT" and info.Type == "MEM_MAPPED"):
                    _Buffer = ctypes.create_string_buffer(info.RegionSize)
                    windll.kernel32.ReadProcessMemory(ProcHandle.handle, LPVOID(info.BaseAddress), _Buffer, info.RegionSize,0)                    
                    if (_Buffer[:116] == bytearray(peHeader)):
                        newFileByteArray = bytes(_Buffer)
                        record = OrderedDict([
                            ("PID:",pid),
                            ("Process Name", ProcName),
                            ("Process Path", ProcPath),
                            ("Reflective DLL load", "True"),
                            ("Base Address", info.BaseAddress),
                            ("Size", info.RegionSize)
                        ])
                        dLst.append(u"{}".format(json.dumps(record))) 
                        with open(str(base_address)+".exe", 'wb') as f:
                            f.write(newFileByteArray)
                next_page = info.BaseAddress + info.RegionSize
                base_address = next_page
        except pywintypes.error as err:
            #print (str(err))
            continue
    return dLst

def printproc(Mlst,Dlst,mName):
    
    if (Mlst != []):
        Mout = open("ModuleScan.json","a+")
        print("Creating a ModuleScan.json file to list processess that load a", mName, " module........")
        for x in Mlst:
            Mout.write(x+"\n")
        Mout.close()
        print("Done...")
    if Dlst != []:
        Dout = open("DLLlst.json","a+")
        print("Creating a DL list.json file to list suspect processes that loaded DLL reflectively........")
        for x in Dlst:
           Dout.write(x+"\n")
        Dout.close()
        print("Done...")

def main(argv=None):
    argv = sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--reflectiveScan", action="store_true",help="Looking for reflective DLL loading")
    parser.add_argument("-m", "--module", action="store", help="Looking for spcefic loaded DLL")
    args = parser.parse_args(argv[1:])
    parser = argparse.ArgumentParser(description="Scan Memory")
    mlst = []
    Dlst = []
    pids = win32process.EnumProcesses()
    if args.module is not None:
        print("Scan for Module ", args.module, ".......")
        mlst = ModuleScan(args.module)
        print("Done...")

    if args.reflectiveScan:
        print("Scan for Reflictive DLL loading ........")
        Dlst = ReflectiveScan()
        print("Done...")

    if (not(args.reflectiveScan) and (args.module is None)):
        print("No arguments were provided")

    printproc(mlst, Dlst, args.module)

if __name__ == "__main__":
    main(argv=sys.argv)
