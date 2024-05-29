
# VolMemLyzer-V2.0.0
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/) ![Static Badge](https://img.shields.io/badge/Tech_Stack-Volatility-red?link=https%3A%2F%2Fgithub.com%2Fvolatilityfoundation%2Fvolatility)


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
* [**Abhay Pratap Singh:**](https://github.com/Abhay-Sengar): Researcher and Developer (VolMemLyzer-V2.0.0)
* [**Beiqi Li:**](https://github.com/beiqil) Developer (Python 2.7 - VolMemLyzer V1.0.0)
* [**Tristan Carrier:**](https://github.com/TristanCarrier) Researcher and developer (Python 2.7 - VolMemLyzer V1.0.0)
* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Researcher (Postdoctorall fellow - VolMemLyzer V1.0.0)


### Acknowledgement 
This project has been made possible through funding from the Natural Sciences and Engineering Research Council grant from Canada—NSERC (\#RGPIN-2020-04701)—to Arash Habibi Lashkari and Mitacs Global Research Internship (GRI) for the researchers. 
