# MemTracer 
MemTracer is a tool that offers live memory analysis capabilities, allowing digital forensic practitioners to discover and investigate stealthy attack traces hidden in memory. The MemTracer is implemented in Python language, aiming to detect reflectively loaded native .NET framework Dynamic-Link Library (DLL). This is achieved by looking for the following abnormal memory region’s characteristics:
- The state of memory pages flags in each memory region. Specifically, the MEM_COMMIT flag which is used to reserve memory pages for virtual memory use.
- The type of pages in the region. The MEM_MAPPED page type indicates that the memory pages within the region are mapped into the view of a section.
- The memory protection for the region. The PAGE_READWRITE protection to indicate that the memory region is readable and writable, which happens if Assembly.Load(byte[]) method is used to load a module into memory.
- The memory region contains a PE header.

<br />The tool starts by scanning the running processes, and by analyzing the allocated memory regions characteristics to detect reflective DLL loading symptoms. Suspicious memory regions which are identified as DLL modules are dumped for further analysis and investigation.
<br />Furthermore, the tool features the following options: 
- Dump the compromised process.
- Export a JSON file that provides information about the compromised process, such as the process name, ID, path, size, and base address. 
- Search for specific loaded module by name. 


# Example
python.exe memScanner.py [-h] [-r] [-m MODULE]
<br />      -h, --help                    show this help message and exit
<br />      -r, --reflectiveScan          Looking for reflective DLL loading
<br />      -m MODULE, --module MODULE    Looking for spcefic loaded DLL

**The script needs administrator privileges in order incepect all processes.**
