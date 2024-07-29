# GetRemoteModuleListW
Retrieve a list of loaded modules of a remote process in Windows, using NtQueryInformationProcess via SysWhispers3
# Index 
[[_TOC_]] Haha, fuck Github
# Overview
I was looking for a way to retrieve a list of loaded DLLs of a remote process without using Windows APIs. OpSec sometimes requires to perform this task with the least possible interaction with calls under surveillance.  
In this current draft the function makes use of *NtQueryInformationProcess* to find the remote process PEB address. I'm quite sure there is a more stealth way to obtain this address, as soon as one has a handle, but I haven't digged into this matter yet - maybe I will come back to this later.  
This repo uses direct syscalls with the [SysWhispers3](https://github.com/klezVirus/SysWhispers3) technique to defy hooking of *NtQueryInformationProcess*. Some typedefs were added manually, like *FULL_LDR_DATA_TABLE_ENTRY*.
# References
* [A dive into the PE format](https://web.archive.org/web/20240728163045/https://0xrick.github.io/win-internals/pe8/)
* [LDR_DATA_TABLE_ENTRY Referece](https://web.archive.org/web/20240728174834/https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html)
* [LDR_DATA_TABLE_ENTRY Sizes](https://web.archive.org/web/20240728163212/https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry.htm)
* [NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
* [SysWhispers is dead, long live SysWhispers](https://web.archive.org/web/20240728163419/https://klezvirus.github.io/RedTeaming/AV_Evasion/NoSysWhisper/)
