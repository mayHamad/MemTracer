# memScanner
memScanner is script written in python language that aims to detect a DLL loaded reflectively. By looking for for unusual memory region’s characteristics:
- The state the pages in the region is MEM_COMMIT that “Indicates committed pages for which physical storage has been allocated, either in memory or in the paging file on disk”.
- The type of pages in the region is MEM_MAPPED that “Indicates that the memory pages within the region are mapped into the view of a section.”
- The allocation protection for the region PAGE_READWRITE. where he page will get read-only and write protection, if Assembly.Load(byte[]) method used to load module into memory.
- The module contains PE header.

<br />Then, the suspected page will be dump for further analysis. Also, the script provides ability of search about specific loaded module by name.

# Example
python.exe memScanner.py [-h] [-r] [-m MODULE]
<br />      -h, --help                    show this help message and exit
<br />      -r, --reflectiveScan          Looking for reflective DLL loading
<br />      -m MODULE, --module MODULE    Looking for spcefic loaded DLL

**The script needs administrator privileges in order incepect all processes.**
