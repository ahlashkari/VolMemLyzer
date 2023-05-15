# VolMemLyzer (Volatility Memory Analyzer)


Memory forensics is a fundamental step that inspects malicious activities during live malware infection. Memory analysis not only captures malware footprints but also collects several essential features that may be used to extract hidden original code from obfuscated malware. There are significant efforts in analyzing volatile memory using several tools and approaches. These approaches fetch relevant information from the kernel and user space of the operating system to investigate running malware. However, the fetching process will accelerate if the most dominating features required for malware classification are readily available. Volatility Memory Analyzer (VolMemLyzer) is a python code to extract more than 36 features to analyze the malicious activities in a memory snapshot using Volatility tool.   

## Example 
python3 VolatilityFeatureExtractor.py -o output.csv memdump_name.raw


## VolatilityFeatureExtractor (First Version)

This is the feature extraction module which use Volatility plugins to extract features and will generate a CSV file as the output.  

### Prerequisites and execution 

For Kali Linux, install volatility via apt:
```
sudo apt install volatility 
```
For other Linux distributions, look for corresponding built-in software repositories, or install https://github.com/volatilityfoundation/volatility from source code. 

Running VolatilityFeatureExtractor 
```
python VolatilityFeatureExtractor.py <path-to-memory-dump> 
```

## VolatilityFeatureExtractor (Second Version)
The memory feature extractor for learning-based solutions with the 26 new features implemented to target obfuscated and hidden malware.

Malfind - commitCharge - Total number of Commit Charges

Malfind - protection - Total number of protection

Malfind - uniqueInjections - Total number of unique injections

Ldrmodule - avgMissingFromLoad - The average amount of modules missing from the load list

Ldrmodule - avgMissingFromInit - The average amount of modules missing from the initilization list

Ldrmodule - avgMissingFromMem - The average amount of modules missing from memory

Handles - port - Total number of port handles

Handles - file - Total number of file handles

Handles - event - Total number of event handles

Handles - desktop - Total number of desktop handles

Handles - key - Total number of key handles

Handles - thread - Total number of thread handles

Handles - directory - Total number of directory handles

Handles - semaphore - Total number of semaphore handles

Handles - timer - Total number of timer handles

Handles - section - Total number of section handles

Handles - mutant - Total number of mutant handles

Process View - pslist - Average false ratio of the process list

Process View - psscan - Average false ratio of the process scan

Process View - thrdproc - Average false ratio of the third process

Process View - pspcid - Average false ratio of the process id

Process View - session - Average false ratio of the session

Process View - deskthrd - Average false ratio of the deskthrd

Apihooks - nhooks - Total number of apihooks

Apihooks - nhookInLine - Total number of in line apihooks

Apihooks - nhooksInUsermode - Total number of apihooks in user mode


### License  
This package is using [**Volatility**](https://github.com/volatilityfoundation/volatility) and following their LICENSE. 

 ## Copyright (c) 2020 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (VolMemLyzer), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
For citation in your works and also understanding VolMemLyzer completely, you can find below published papers:
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

- Tristan Carrier, Princy Victor, Ali Tekeoglu, Arash Habibi Lashkari, "Detecting Obfuscated Malware Using Memory Feature Engineering", In the proceeding of the 8th International Conference on Information Systems Security and Privacy (ICISSP), 2022


### Project Team members 

* [**Arash Habibi Lashkari:**](http://ahlashkari.com/index.asp) Founder and Project Owner 

* [**Beiqi Li:**](https://github.com/beiqil) Developer (Python 2.7)

* [**Tristan Carrier:**](https://github.com/TristanCarrier) Researcher and developer (Python 2.7)

* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Researcher (Postdoctorall fellow) 

### Acknowledgement 
This project has been made possible through funding from the NSERC-Discovery from 2021 to 2026. 
