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

 ![Volatility3Cloned](https://github.com/user-attachments/assets/8bdb057d-1c97-427a-90c6-69d305e5f9e3)
 
![PythonPip3Install](https://github.com/user-attachments/assets/8c11c290-4549-4f65-97af-f423d2c4ffac)

I began the lab by cloning the Volatility 3 repository from GitHub using the git clone commmand. Next, I installed the necessary dependencies with the sudo apt install command. I verified the installation by running vol.py -h to confirm the tool was set up correctly. 

![PSScan](https://github.com/user-attachments/assets/9166f9ef-8f14-4a74-8380-17ad9c56bf46)
I Then ran the command python3 vol.py -f infected.vmem windows.psscan to 
![PSScanResult](https://github.com/user-attachments/assets/c82ad769-7334-4649-99fc-f1e52f4ca2d1)




