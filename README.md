# **CVE-2024-30090 - LPE PoC**
[CVE-2024-30090](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30090) found by [Angelboy](https://x.com/scwuaptx) with DEVCORE.

## **Parent.cpp** 
Get the ntoskrnl base by using NtQuerySystemInformation (medium-integrity) - **Compile as x64**.

## **Child.cpp**
The exploit for CVE-2024-30090 - **Compile as x86**.

## **Thanks**
**Big** thanks [Angelboy](https://x.com/scwuaptx) for your help and guidance!.  
[Cedric Halbronn ](https://x.com/saidelike) 'OST2 - Exploitation 4011 - Windows Kernel Exploitation' - `winhelpers.h`.  
[bruno-1337](https://github.com/bruno-1337) - [SeDebugPrivilege-Exploit](https://github.com/bruno-1337/SeDebugPrivilege-Exploit).

## **Resources & References**
1. [Streaming vulnerabilities from Windows Kernel - Proxying to Kernel - Part I](https://devco.re/blog/2024/08/23/streaming-vulnerabilities-from-windows-kernel-proxying-to-kernel-part1-en/)
2. [Streaming vulnerabilities from Windows Kernel - Proxying to Kernel - Part II](https://devco.re/blog/2024/10/05/streaming-vulnerabilities-from-windows-kernel-proxying-to-kernel-part2-en/)
3. [Streaming vulnerabilities from Windows Kernel - Proxying to Kernel - CVE-2024-30090](https://www.youtube.com/watch?v=m2TNVDgz7CI)