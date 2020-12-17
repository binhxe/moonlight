# Context
https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html

# DGA Algrorithm

The C2 domain has the format **[DGA].[hard-coded values for subdomains and domain]**

The **[DGA]** is in the format **[part1][part2][part3]** where:
  * [part1] 15 charcters : Encoded string derived from the MAC address of the first non loopback network card with status UP
  * [part2] 1 characters : Encoded string derived from first character of <part1>
  * [part3] n characters : Encoded string derived from Active Directory name that the computer registered to. Sunburst obtains this value by calling
    [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
    
# moonlight.ps1

The script will generate the **[part3]** which can be used for detection with proxy logs

99% of code are ported from sunburst C# code

# Usage

* .\moonlight.ps1

The Active Directory Domain Name will be obtained by calling [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
 
* .\moonlight.ps1 -ADomain \<Active Directory Domain>

User provides the Active Directory Domain Name. The DGA algorithm is case sensitive, to mimic sunburst, the value should be obtained by calling [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName

* Example:

.\moonlight.ps1 -ADomain sunburst.local

Output : **Splunk query example: index=proxylogs dest_host=*6fvcfsi0h12eu1* | fields + dest_host**
