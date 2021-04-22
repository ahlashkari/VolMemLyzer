# VolMemLyzer (Volatility Memory Analyzer)


Memory forensics is a fundamental step that inspects malicious activities during live malware infection. Memory analysis not only captures malware footprints but also collects several essential features that may be used to extract hidden original code from obfuscated malware. There are significant efforts in analyzing volatile memory using several tools and approaches. These approaches fetch relevant information from the kernel and user space of the operating system to investigate running malware. However, the fetching process will accelerate if the most dominating features required for malware classification are readily available. Volatility Memory Analyzer (VolMemLyzer) is a python code to extract more than 36 features to analyze the malicious activities in a memory snapshot using Volatility tool.   

 
## VolatilityFeatureExtractor (First Package)

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

## Analyzer (Second Package)
TBD

### Contributing 
The project is currently in development, but any contribution is welcome in form of pull requests. 


### License  
This package is using [**Volatility**](https://github.com/volatilityfoundation/volatility) and following their LICENSE. 

 ## Copyright (c) 2020 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (VolMemLyzer), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
For citation in your works and also understanding VolMemLyzer completely, you can find below published papers:

Arash Habibi Lashkari, Beiqi Li, Tristan Lucas Carrier, Gurdip Kaur, VolMemLyzer: Volatile Memory Analyzer for Malware Classification using Feature Engineering", Reconciling Data Analytics, Automation, Privacy, and Security: A Big Data Challenge (RDAAPS), IEEE 978-1-7281-6937-8/20, Canada, ON, McMaster University, 2021

### Project Team members 

* [**Arash Habibi Lashkari:**](https://www.cs.unb.ca/~alashkar/) Founder and Project Owner 

* [**Gurdip Kaur:**](https://www.linkedin.com/in/gurdip-kaur-738062164/) Researcher

* [**Beiqi Li:**](https://github.com/beiqil) Developer 

 

### Acknowledgement 
This project has been made possible through funding from the NSERC-Discovery from 2020 to 2025. 
