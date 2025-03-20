## Ransomware-Lab-Analysis - Devin Cox


# Objective 
 analyze a memory dump to identify indicators of ransomware activity. This includes locating malicious processes, identifying encryption patterns and tracing execution paths using Volatility3 in linux.

 # Skills Learned 
- Using Volatility 3 to analyze memory dumps
- Identifying malicious processes and hidden artifacts
- Tracing parent-child relationships with pstree
- Detecting injected or unlinked processes using psscan
- Analyzing ransomware execution patterns and memory artifacts


 # Tools

 <div>
    <img src="https://img.shields.io/badge/-Kali%20Purple-557C94?&style=for-the-badge&logo=Kali%20Linux&logoColor=white" />
</div>

<div>
    <img src="https://img.shields.io/badge/-Volatility%203-3A3A3A?&style=for-the-badge&logo=Volatility&logoColor=white" />
</div>

<div>
    <img src="https://img.shields.io/badge/-VirtualBox-183A61?&style=for-the-badge&logo=VirtualBox&logoColor=white" />
</div>

<div>
    <img src="https://img.shields.io/badge/-VirusTotal-4682B4?&style=for-the-badge&logo=VirusTotal&logoColor=white" />
</div>

<div>
    <img src="https://img.shields.io/badge/-Mandiant-FF0000?&style=for-the-badge&logo=FireEye&logoColor=white" />
</div>

 # Write-Up

 <img width="595" alt="BTLO-Scenario" src="https://github.com/user-attachments/assets/e21c1acb-c3ba-4121-a7c2-f6132bdb443b" />

 I began the lab by cloning the Volatility 3 repository from GitHub using the git clone commmand "git clone https: //github.com/volatilityfoundation/volatility3.git". Next, I installed the necessary dependencies with the sudo apt install command. I verified the installation by running "vol.py -h" to confirm the tool was set up correctly. 

 ![Volatility3Cloned](https://github.com/user-attachments/assets/8bdb057d-1c97-427a-90c6-69d305e5f9e3)
 
![PythonPip3Install](https://github.com/user-attachments/assets/8c11c290-4549-4f65-97af-f423d2c4ffac)


![PSScan](https://github.com/user-attachments/assets/9166f9ef-8f14-4a74-8380-17ad9c56bf46)

Next, I executed the command python3 vol.py -f infected.vmem windows.psscan to perform a raw memory scan for hidden or unlinked processes. This approach allows for the identification of terminated or rootkit-masked processes that may not appear in the active process list.
![PSScanResult](https://github.com/user-attachments/assets/c82ad769-7334-4649-99fc-f1e52f4ca2d1)
 After looking through the psscan, I put the results into a notepad file and I located the suspiscous process called "@WannaDecryptor" with the PPID of 2732

![SusProcessNameZoomed](https://github.com/user-attachments/assets/fae32b37-4680-4aab-bfc9-26db6cf43bb7)

<img width="951" alt="PsTreeScan" src="https://github.com/user-attachments/assets/d09a8b02-4435-4c5c-9ca9-2951081c3233" />

Next, I executed a PsTree scan to analyze the parent-child process hierarchy and identify the executable associated with the Parent Process ID (PPID) 2732. I exported the results to a text file for further examination and utilized the CTRL-F search function to quickly locate entries linked to this PPID. This analysis revealed an executable named "or4qtckT.exe", indicating a potentially suspicious process.

![PStreeScanExeFound](https://github.com/user-attachments/assets/f60e73f4-a2f0-4d8a-8fdc-d3b9b7c2312a)

After finding the executable file I used the grep command on the PID, "2732" to check if it was linked to any other processes. The results of the command displayed a third process called taskdl.exe

<img width="951" alt="PsScanGrepped2732" src="https://github.com/user-attachments/assets/73d4b762-124d-4d3c-a917-954f55d3271c" />

Next, I performed a memory dump of the executable associated with PID 2732 using the following command: "python3 vol.py -f infected.vmem windows.psscan --pid 2732 --dump". This operation extracted the process memory and generated an output file named "2732.or4qtckT.exe.0x400000.dmp", allowing for further analysis of the executable’s contents.
<img width="950" alt="SuccesfulFileDump" src="https://github.com/user-attachments/assets/e6d1fc58-351a-4605-a08d-e2ceb5574fb4" />

After extracting the memory dump, I computed its SHA-256 hash using the following command: "sha256sum 2732.or4qtckT.exe.0x400000.dmp" This generated a unique cryptographic hash of the dumped executable, which I then submitted to VirusTotal to determine potential malicious characteristics.

<img width="632" alt="DumpedFileLookupandHash" src="https://github.com/user-attachments/assets/04f4f5c5-e7f2-4a9a-a786-d0388bde5ca2" />

After submitting the computed SHA-256 hash to VirusTotal, the analysis report indicated that the file was flagged as malicious by 48 security vendors. The identified malware was classified as "WannaCry," a known ransomware variant.

<img width="950" alt="VirusTotalHashScan" src="https://github.com/user-attachments/assets/e1779244-d449-40d3-bb83-b877a0e2ce62" />

After identifying the malware as WannaCry, I conducted further research to gather threat intelligence on its characteristics and behavior. Utilizing open-source intelligence (OSINT), I searched for a comprehensive malware profile and found that Mandiant, a well-established cybersecurity firm, had published a detailed analysis of the ransomware, providing insights into its tactics, techniques, and indicators of compromise (IOCs).

<img width="958" alt="WannaCryMalwareProfile" src="https://github.com/user-attachments/assets/4af949ac-8396-436b-8da2-418a79531553" />

While analyzing the malware profile, I identified the third executable associated with the WannaCry infection. According to the report, this executable functions as a file deletion utility.

<img width="566" alt="FileDeletionTool" src="https://github.com/user-attachments/assets/9043562e-a67f-447d-9854-198878fa0c6f" />

In the report it identifies a public RSA encryption key named "00000000.eky." This key was utilized to encrypt the private decryption key, preventing victims from accessing their encrypted files without the corresponding private key, which is typically held by the attacker.

<img width="632" alt="PublicFileEncoderKey" src="https://github.com/user-attachments/assets/98b1004c-52c2-45e4-89be-4f7cb81961d9" />

# Conclusion 

In this lab, I conducted an in-depth memory forensics investigation on a compromised system infected with WannaCry ransomware. Using Volatility 3, I systematically analyzed the memory dump to identify hidden processes, malicious executables, and encryption artifacts.

Key findings included:

- Detection of the WannaCry ransomware process (@WannaDecryptor) using psscan.
- Identification of suspicious process relationships via pstree, revealing how the ransomware executed.
- Extraction of the malicious executable from memory using procdump for further analysis.
- Calculation of the SHA-256 hash of the dumped malware and submission to VirusTotal, confirming its classification as WannaCry.
- Discovery of the public RSA encryption key (00000000.eky), which was used to encrypt the private key required for file decryption.

 By leveraging process analysis, memory extraction, and threat intelligence, I was able to reconstruct the attack chain and identify key artifacts essential for further mitigation and response. This lab reinforced the critical role of forensic techniques in cybersecurity and incident response, providing valuable hands-on experience in ransomware investigation and malware analysis.


