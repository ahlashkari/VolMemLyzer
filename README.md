
# VolMemLyzer (Volatile Memory Analyzer)
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)


Memory forensics is essential in cybersecurity and digital forensics, especially for fighting advanced threats and malware. In this dynamic environment, memory analysis tools and methods must be efficient. By prioritising the prominent features in a memory, investigators can speed up their analysis.
The **VolMemLyzer** (Volatile Memory Analyzer) can extract over **250 features** from memory snapshots, speeding up analysis and enabling deeper explorations. It serves as a catalyst for memory forensics research and innovation.

The new VolMemLyzer-V2 is a tool based on **functional programming paradigm** with dependencies on updated Volatility3 Framework based on python 3.

## Extracted Features

The taxonoy of the features produced by VolMemLyzer which based on plugin structure is summarised below using this interactive sunburst chart:


![Alt text](images/VolMemLyzerBurstGIF.gif)

## Pre-requisites

#### Volatility

For Linux, install **volatility** via apt:
```bash
  sudo apt install volatility 
```
For other Linux distributions, look for corresponding built-in software repositories, or install https://github.com/volatilityfoundation/volatility from source code.
#### Other Pre-requisites

Out of all libraries used, only **pandas** library is not part of the Python standard library and must be installed separately using pip via:
```bash
  pip install pandas
```


## Deployment

#### Step 1:
Complete pre-requisites and download the VolMemLyzer script from above to the desired folder. Navigate to the folder where the script was downloaded and initiate terminal/powershell in the folder.

#### Step 2:
Use the command given below:

```bash
  python3 VolMemLyzer-V2.py -f <Path to Memory Dump Folder> -o <Path to Output Folder> -V <Path to Volatility3>
```

The Placeholders should strictly follow:
- **Path to Memory Dump Folder** - This should be an absolute path to the folder containing memory dump files. Ex: */home/user1/Desktop/MemoryDumps*
- **Path to Output Folder** - This should be an absolute path to the folder where the *output.csv* is to be stored. Ex: */home/user1/Desktop/VolMemLyzerOutput*
- **Path to Volatility3** - This should be an absolute path to the *vol.py* file in the downloaded volatility folder from official Volatility3 Github. Ex: */home/user1/Desktop/Volatility3/vol.py*


### Features 
Here is the list of features that VolMemLyzer V2.0.0 will stract from each memory snapshot:
1. mem name
	- mem.name_extn
2. info
  	- info.Is64
	- info.winBuild
	- info.npro	
	- info.IsPAE	
3. PsList
	- pslist.nproc	
	- pslist.nppid	
	- pslist.avg_threads	
	- pslist.avg_handlers	
	- pslist.nprocs64bit	
	- pslist.outfile
4. DLLList	
	- dlllist.ndlls	
	- dlllist.nproc_dll	
	- dlllist.avg_dllPerProc	
	- dlllist.avgSize	
	- dlllist.outfile	
5. Handles
	- handles.nHandles	
	- handles.distinctHandles	
	- handles.nproc	
	- handles.nAccess	
	- handles.avgHandles_per_proc	
	- handles.nTypePort	
	- handles.nTyepProc	
	- handles.nTypeThread	
	- handles.nTypeKey	
	- handles.nTypeEvent	
	- handles.nTypeFile	
	- handles.nTypeDir	
	- handles.nTypeSec	
	- handles.nTypeDesk	
	- handles.nTypeToken	
	- handles.nTypeMutant	
	- handles.nTypeKeyEvent	
	- handles.nTypeSymLink	
	- handles.nTypeSemaph	
	- handles.nTypeWinSta	
	- handles.nTypeTimer	
	- handles.nTypeIO	
	- handles.nTypeWmi	
	- handles.nTypeWaitPort	
	- handles.nTypeJob	
	- handles.nTypeUnknown	
6. Idr Modules
	- ldrmodules.total	
	- ldrmodules.not_in_load	
	- ldrmodules.not_in_init	
	- ldrmodules.not_in_mem	
	- ldrmodules.nporc	
	- ldrmodules.not_in_load_avg	
	- ldrmodules.not_in_init_avg	
	- ldrmodules.not_in_mem_avg	
7. MalFind
	- malfind.ninjections	
	- malfind.commitCharge	
	- malfind.protection	
	- malfind.uniqueInjections	
	- malfind.avgInjec_per_proc	
	- malfind.tagsVad	
	- malfind.tagsVads	
	- malfind.aveVPN_diff	
	- modules.nmodules	
	- modules.avgSize	
	- modules.FO_enabled	

8. Call Backs
	- callbacks.ncallbacks	
	- callbacks.nNoDetail	
	- callbacks.nBugCheck	
	- callbacks.nBugCheckReason	
	- callbacks.nCreateProc	
	- callbacks.nCreateThread	
	- callbacks.nLoadImg	
	- callbacks.nRegisterCB	
	- callback.nUnknownType	

9. CMD Line
	- cmdline.nLine	
	- cmdline.not_in_C	
	- cmdline.n_exe	
	- cmdline.n_bin	

10. Device Tree
	- devicetree.ndevice	
	- devicetree.nTypeNotDRV	

11. Driverirp (Driver IRP hook detection)
	- driverirp.nIRP	
	- driverirp.nModules	
	- driverirp.nSymbols	
	- driverirp.n_diff_add	
	- drivermodule.nModules	
	- driverscan.nscan	
	- driverscan.avgSize	
12. envars (Display process environment variables)
	- envars.nVars	
	- envars.nProc	
	- envars.nBlock	
	- envars.n_diff_var	
	- envars.nValue	
13. File Scan
	- filescan.nFiles	
	- filescan.n_diff_file	
14. getsid (The SIDs owning each process)
	- getsids.nSIDcalls	
	- getsids.nProc	
	- getsids.nDiffName	
	- getsids.n_diff_sids	
	- getsids.avgSIDperProc	
15. MBRScan (Scans Master Boot Records (MBRs))
	- mbrscan.nMBRentries	
	- mbrscan.nDiskSig	
	- mbrscan.nPartType	
	- mbrscan.bootable	

16. MFTScan (Scan for potential MFT entries)
	- mftscan.nEntriesMFT	
	- mftscan.nAttributeType	
	- mftscan.nRecordType	
	- mftscan.AvgRecordNum	
	- mftscan.AvgLinkCount	
	- mftscan.0x9_typeMFT	
	- mftscan.0xd_typeMFT	
	- mftscan.DirInUse_typeMFT	
	- mftscan.Removed_typeMFT	
	- mftscan.File_typeMFT	
	- mftscan.Other_typeMFT	
	- mftscan.AvgChildren	

17. ModScan (Pool scanner for kernel modules)
	- modscan.nMod	
	- modscan.nUniqueExt	
	- modscan.nDLL	
	- modscan.nSYS	
	- modscan.nEXE	
	- modscan.nOthers	
	- modscan.AvgSize	
	- modscan.MeanChildExist	
	- modscan.FO_Enabled	

18.mutanscan (Pool scanner for mutex objects) 
	- mutantscan.nMutantObjects	
	- mutantscan.nNamedMutant	

19. net scan (Scan a Vista (or later) image for connections and sockets)
	- netscan.nConn	
	- netscan.nDistinctForeignAdd	
	- netscan.nDistinctForeignPort	
	- netscan.nDistinctLocalAddr	
	- netscan.nDistinctLocalPort	
	- netscan.nOwners	
	- netscan.nDistinctProc	
	- netscan.nListening	
	- netscan.Proto_TCPv4	
	- netscan.Proto_TCPv6	
	- netscan.Proto_UDPv4	
	- netscan.Proto_UDPv6	

20. netstat (network active connections)
	- netstat.nConn	
	- netstat.nDistinctForeignAdd	
	- netstat.nUnexpectForeignAdd	
	- netstat.nDistinctLocalAddr	
	- netstat.nUnexpectLocalAddr	
	- netstat.nDistinctLocalPort	
	- netstat.nOwners	
	- netstat.nDistinctProc	
	- netstat.nListening	
	- netstat.nEstablished	
	- netstat.nClose_wait	
	- netstat.Proto_TCPv4	
	- netstat.Proto_TCPv6	
	- netstat.Proto_UDPv4	
	- netstat.Proto_UDPv6	
	- netstat.nNaNPID	

21. Pool Scanner
	- poolscanner.nPool	
	- poolscanner.nUniquePool	

22. Privileges
	- privileges.nTotal	
	- privileges.nUniquePrivilege	
	- privileges.nPID	
	- privileges.nProcess	
	- privileges.nAtt_D	
	- privileges.nAtt_P	
	- privileges.nAtt_PE	
	- privileges.nAtt_PED	
	- privileges.nAtt_NaN	

23. PSTree (process list as a tree)
	- pstree.nTree	
	- pstree.nHandles	
	- pstree.nPID	
	- pstree.nPPID	
	- pstree.AvgThreads	
	- pstree.nWow64	
	- pstree.AvgChildren	

24. Registry
	- registry.certificates.nCert	
	- registry.certificates.nID_Auto	
	- registry.certificates.nID_Protected	
	- registry.certificates.nID_Others	
	- registry.hivelist.nFiles	
	- registry.hivelist.nFO_Enabled	
	- registry.hivescan.nHives	
	- registry.hivescan.Children_exist	
	- registry.printkey.nKeys	
	- registry.printkey.nDistinct	
	- registry.printkey.nType_key	
	- registry.printkey.nType_other	
	- registry.printkey.Volatile_0	
	- registry.printkey.Avg_Children	
	- registry.userassist.n	
	- registry.userassist.nUnique	
	- registry.userassist.Avg_Children	
	- registry.userassist.path_DNE	
	- registry.userassist.type_key	
	- registry.userassist.type_other	

25. Sessions (details on _MM_SESSION_SPACE (user logon sessions))
	- sessions.nSessions	
	- sessions.nProcess	
	- sessions.nUsers	
	- sessions.nType	
	- sessions.Children_exist	

26. Skeleton Key
	- skeleton_key.nKey		
	- skeleton_key.nProcess	
	- skeleton_key.Found_True	
	- skeleton_key.Found_False	

27. ssdt (SSDT entries)
	- ssdt.n	
	- ssdt.nIndex	
	- ssdt.nModules	
	- ssdt.nSymbols	
	- ssdt.Children_exist	

28. Statistics
	- statistics.Invalid_all	
	- statistics.Invalid_large	
	- statistics.Invalid_other	
	- statistics.Swapped_all	
	- statistics.Swapped_large	
	- statistics.Valid_all	
	- statistics.Valid_large	

29. SVScan (Scan for Windows services)
	- svcscan.nServices	
	- svcscan.nUniqueServ	
	- svcscan.State_Run	
	- svcscan.State_Stop	
	- svcscan.Start_Sys	
	- svcscan.Start_Auto	
	- svcscan.Type_Own_Share	
	- svcscan.Type_Own	
	- svcscan.Type_Share	
	- svcscan.Type_Own_Interactive	
	- svcscan.Type_Share_Interactive	
	- svcscan.Type_Kernel_Driver	
	- svcscan.Type_FileSys_Driver	
	- svcscan.Type_Others	

30. symlinksscan (Pool scanner for symlink objects)
	- symlinkscan.nLinks	
	- symlinkscan.nFrom	
	- symlinkscan.nTo	
	- symlinkscan.Avg_Children	

31. vad info (Dump the VAD info)
	- vadinfo.nEntries	
	- vadinfo.nFile	
	- vadinfo.nPID	
	- vadinfo.nParent	
	- vadinfo.nProcess	
	- vadinfo.Process_Malware	
	- vadinfo.Type_Vad	
	- vadinfo.Type_VadS	
	- vadinfo.Type_VadF	
	- vadinfo.Type_VadI	
	- vadinfo.Protection_RO	
	- vadinfo.Protection_RW	
	- vadinfo.Protection_NA	
	- vadinfo.Protection_EWC	
	- vadinfo.Protection_WC	
	- vadinfo.Protection_ERW	
	- vadinfo.Avg_Children	

32. vadwalk (Walk the VAD tree)
	- vadwalk.Avg_Size	

33. ver info (version information from PE images)
	- verinfo.nEntries	
	- verinfo.nUniqueProg	
	- verinfo.nPID	
	- verinfo.Avg_Children	

34. virtmap (virtual file in memory)
	- virtmap.nEntries	
	- virtmap.Avg_Offset_Size	
	- virtmap.Avg_Children



## Improvements (V2.0.0 vs V1.0.0)
- Now supports 250+ features compared to less than 75 earlier.
- Supports latest Volatility 3 Framework rather than outdated Volatility 2 Framework.
- Now runs on python 3 rather than python 2.
- Improved redundancy - Exception handling support if dataframe is not created or incorrectly created.
- Improved computability with pandas.
- Scope of types of files supported increased.

NOTE: Future updates should include support for more third party plugins and better exception handling capabilities.


### License  
This package is using [**Volatility**](https://github.com/volatilityfoundation/volatility) and following their LICENSE. 

## Copyright (c) 2020 and Citation
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (VolMemLyzer), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


For citation VolMemLyzer V2.0.0, in your works and also understanding it completely, you can find below published papers:



For citation VolMemLyzer V1.0.0, in your works and also understanding it completely, you can find below published papers:

```
@INPROCEEDINGS{9452028,
  author={Lashkari, Arash Habibi and Li, Beiqi and Carrier, Tristan Lucas and Kaur, Gurdip},
  booktitle={2021 Reconciling Data Analytics, Automation, Privacy, and Security: A Big Data Challenge (RDAAPS)}, 
  title={VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering}, 
  year={2021},
  volume={},
  number={},
  pages={1-8},
  doi={10.1109/RDAAPS48126.2021.9452028}}
```



### Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and Project Owner
* [**Yassin Dehfuli:**](https://github.com/YaCnDehfuli): Master Student, Researcher and Developer (Python 3.0 - VolMemLyzer-V3.0.0) 
* [**Abhay Pratap Singh:**](https://github.com/Abhay-Sengar): Undergraduate Student, Researcher and Developer (Python 3.0 - VolMemLyzer-V2.0.0)
* [**Beiqi Li:**](https://github.com/beiqil) Undergraduate Student, Developer (Python 2.7 - VolMemLyzer V1.0.0)
* [**Tristan Carrier:**](https://github.com/TristanCarrier) Master Student, Researcher, and developer (Python 2.7 - VolMemLyzer V1.0.0)
* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Postdoctorall Fellow Researcher (Python 2.0 - VolMemLyzer V1.0.0)


### Acknowledgement 
This project has been made possible through funding from the Natural Sciences and Engineering Research Council grant from Canada—NSERC (\#RGPIN-2020-04701)—to Arash Habibi Lashkari and Mitacs Global Research Internship (GRI) for the researchers. 
