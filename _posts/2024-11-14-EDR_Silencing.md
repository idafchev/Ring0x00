---
date:   2024-11-14
title:  "Alternative ways for EDR Silencing"
excerpt: "Assigning secondary IP addresses and IPSec filter rules to block EDR communication"
toc: true
tags:
  - posts
  - edr
  - silencing
  - offsec
  - offensive
---
# Introduction  
---
Using the Windows Filtering Platform (WFP) APIs or creating specific Windows Firewall rules are well-known methods to silence EDRs. Popular tools using WFP for silencing are [EDRSilencer](https://github.com/netero1010/EDRSilencer), [Shutter](https://github.com/dsnezhkov/shutter), [EDRPrison](https://github.com/senzee1984/EDRPrison). But recently, a colleague shared a paper with me detailing an alternative approach to silence EDRs which piqued my interest and led me to explore other potential methods for disrupting EDR communication on my own.  

# Sinkholing by assigning secondary IP addresses  
---
A network interface can be configured with more than one IP address. By assigning a secondary IP address that matches a public host’s IP, you effectively make that host unreachable. This works because traffic intended for that public IP is redirected to your local interface instead of reaching the actual remote host. This technique essentially acts as a form of sinkholing, where traffic to a target IP is absorbed locally.  

To silence an EDR, you need to identify the IP addresses it communicates with. Once identified, you can assign each of these IPs (or their entire subnet) as secondary addresses on your interface.

To manually add a secondary IP address, go to:  
`Adapter Properties > IPv4 > Properties > Advanced > IP Settings`  

![Assigning Secondary IP](https://idafchev.github.io/blog/assets/images/edr_silencing/secondary_ip.png){: .align-center}  

**Note:** If the network adapter is set to obtain its IP address automatically via DHCP, secondary addresses cannot be added. In this case, you must convert the adapter configuration to use static IP addressing by copying the current network settings.
{: .notice--info}

Identifying specific IP addresses for each EDR can be inconvenient, as these IPs may change frequently or use failover IPs for redundancy. To streamline this process, it’s more effective to block connections based on process names rather than individual IP addresses.  

To address this, I developed a PowerShell script ([IPMute](https://github.com/idafchev/IPMute/blob/main/ipmute.ps1)) that continuously monitors a specified list of processes for TCP connections, captures each connection’s remote address, and assigns it as a secondary IP address on all active physical adapters. Upon exiting with `CTRL+C`, the script performs a cleanup, removing all blocked IP addresses.

You need to let it run for a while to make sure all IP addresses are discovered by the script. The example below targets normal processes as I don't want to give examples with an actual product.  

![IPMute](https://idafchev.github.io/blog/assets/images/edr_silencing/ip_mute.png){: .align-center}  

![IPMute result](https://idafchev.github.io/blog/assets/images/edr_silencing/secondary_ip_2.png){: .align-center}  

Static IP settings are stored in the following Registry value:  
```
HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}\IPAddress
```  
This means that this technique could potentially be made ineffective in a similar manner to the one outlined in the Huntress article, "[Silencing the EDR Silencers](https://www.huntress.com/blog/silencing-the-edr-silencers)".  

Depending how the secondary IP addresses are added, the registry values are modified by a different process:  
- `wmiprvse.exe` if addresses were added with powershell cmdlets.  
- `DllHost.exe` if addresses were added from GUI.  
- `netsh.exe` if addresses were added by netsh.  
- `svchost.exe` if assigned by DHCP (but the registry value is DhcpIPAddress).  

![Procmon](https://idafchev.github.io/blog/assets/images/edr_silencing/procmon.png){: .align-center}  

These specifics could be useful in creating detections for scripted IP configuration changes.  

Additionally, it is possible to add secondary IP addresses directly in the registry. However, in my testing, changes to this registry setting did not take effect unless I manually disabled and then re-enabled the network interface. Could be interesting to reverse how the Windows commands are assigning them without disable/re-enable of the interface. Maybe it's possible to do it programatically.    

# IPSec filter rules
It's not new that IPSec filter rules can be used to filter traffic, even if you don't have IPSec configured (you can check the blog "[Windows IPSEC for endpoint quarantine](https://mgreen27.github.io/posts/2020/07/23/IPSEC.html)" for more information). Therefore such rules can also be used for the malicious purpose to block EDR communication. An example of how to use the `netsh` command to set IPSec filter rules is shown below. 

The filterlist can also accept domain names, but what actually happens is that several rules are created which block all IPs to which the domain currently resolves to.
{: .notice--info}

```bat
netsh ipsec static add policy name=BlockPolicy description=BlockPolicy
netsh ipsec static set policy name=BlockPolicy assign=y

:: Command examples for filterlist. One or several can be used.
:: netsh ipsec static add filter filterlist=BlockFilterList srcaddr=me dstaddr=X.X.X.X protocol=tcp description="FilterList"
:: netsh ipsec static add filter filterlist=BlockFilterList srcaddr=me dstaddr=X.X.X.X dstmask=24 protocol=tcp description="FilterList"
:: netsh ipsec static add filter filterlist=BlockFilterList srcaddr=me dstaddr=X.X.X.X Y.Y.Y.Y dstmask=32 protocol=tcp description="FilterList"
:: netsh ipsec static add filter filterlist=BlockFilterList srcaddr=me dstaddr=X.X.X.X-Y.Y.Y.Y dstmask=32 protocol=tcp description="FilterList"
:: netsh ipsec static add filter filterlist=BlockFilterList srcaddr=me dstaddr=DOMAIN.COM protocol=tcp description="FilterList"

netsh ipsec static add filteraction name=BlockFilterAction action=block
netsh ipsec static add rule name=BlockRule policy=BlockPolicy filterlist=BlockFilterList filteraction=BlockFilterAction description="IPSec Block Rule"
```

Because I hate writing batch, I asked ChatGPT to create a general script with a configurable list of IP addresses, IP ranges, or domain names, which are subsequently blocked via IPSec filter rules. Any empty list is ignored - [IPSecFilter](https://github.com/idafchev/IPSecFilter/blob/main/ipsecfilter.bat)  

To list all ipsec filter rules:  
```bat
netsh ipsec static show all
```  

To remove the policy, along with all associated rules, filters, and lists: 
```bat
netsh ipsec static delete policy name=BlockPolicy
```  

IP addresses from the IPSec filterlist are stored in the registry as hex values at the following location:  
```
HKLM\Software\Policies\Microsoft\Windows\IPSec\Policy\Local\ipsecFilter{GUID}\ipsecData
```  
The process which adds the registry values is `netsh`.

Because configuration is stored in registry, it means that it could be made ineffective with the technique discussed in the Huntress article meantioned in previous section.

I couldn't find if IPSec filters can be configured programmatically using the Windows Filtering Platform (WFP) API or another API, but this could be a promising for further research.

# DNS Sinkholing
## Adding the EDR domains to the hosts file
Again, nothing new here. Research what domains the target EDR is connecting to and add them to the hosts file, directing them to `127.0.0.1`.

```
C:\Windows\System32\drivers\etc\hosts
```  

There is a disadvantage with this approach. Even if you clear the DNS cache with `ipconfig /flushdns` or kill the already established TCP connections with sysinternals `TCPView`, the resolutions might have been cached in the process itself and connections may continue to be made to the original destination. You may need to wait for extended period of time or a re-boot for this to fully take effect.

Or the EDR may connect to certain IPs directly.

## Changing the DNS to one under attacker control
Another way is if you can change the current DNS to one under your control and sinkhole on the DNS server side.
Or use a free service like OpenDNS which gives you DNS filtering capabilities.

If you block the EDR domains in OpenDNS, then set the local host DNS settings to point to OpenDNS you get the same sinkholing effect.
But it has the same disadvantage. The remote IPs may have alraedy been cached in the process itself and you may have to wait for extended period of time or a re-boot for the EDR process to start using the new IP.

# Resources
---
1. [Silencing the EDR Silencers](https://www.huntress.com/blog/silencing-the-edr-silencers)  
2. [EDRSilencer project](https://github.com/netero1010/EDRSilencer)  
3. [Shutter project](https://github.com/dsnezhkov/shutter)  
4. [EDRPrison project](https://github.com/senzee1984/EDRPrison)  
5. [Windows IPSEC for endpoint quarantine](https://mgreen27.github.io/posts/2020/07/23/IPSEC.html)  
