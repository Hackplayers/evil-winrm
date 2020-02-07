# Evil-WinRM [![Version-shield]](evil-winrm.rb) [![Ruby2.3-shield]](https://www.ruby-lang.org/en/news/2015/12/25/ruby-2-3-0-released/) [![Gem-Version]](https://rubygems.org/gems/evil-winrm) [![License-shield]](LICENSE) [![Docker-shield]](https://hub.docker.com/r/oscarakaelvis/evil-winrm)
The ultimate WinRM shell for hacking/pentesting

![Banner](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/evil-winrm_logo.png)

## Description & Purpose
This shell is the ultimate WinRM shell for hacking/pentesting.

WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol 
that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating 
Systems in order to make life easier to system administrators.

This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985), of course only 
if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting 
phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate 
purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.

## Features
 - Compatible to Linux and Windows client systems
 - Load in memory Powershell scripts
 - Load in memory dll files bypassing some AVs
 - Load in memory C# (C Sharp) assemblies bypassing some AVs
 - Load x64 payloads generated with awesome [donut] technique
 - AMSI Bypass
 - Pass-the-hash support
 - Kerberos auth support
 - SSL and certificates support
 - Upload and download files showing progress bar
 - List remote machine services without privileges
 - Command History
 - WinRM command completion
 - Local files completion
 - Colorization on prompt and output messages (can be disabled optionally)
 - Docker support (prebuilt images available at [Dockerhub])
 - Trap capturing to avoid accidental shell exit on Ctrl+C

## Help
```
Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname (required)
    -U, --url URL                    Remote url endpoint (default wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash NTHash                NTHash 
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -h, --help                       Display this help message
```

## Requirements
Ruby 2.3 or higher is needed. Some ruby gems are needed as well: `winrm >=2.3.2`, `winrm-fs >=1.3.2`, `stringio >=0.0.2`.
Depending of your installation method (3 availables) the installation of them could be required to be done manually.

Another important requirement only used for Kerberos auth is to install the Kerberos package used for network authentication.
For some Linux like Debian based (Kali, Parrot, etc.) it is called `krb5-user`. For BlackArch it is called `krb5` and probably it could be called in a different way for other Linux distributions.

## Installation & Quick Start (4 methods)

### Method 1. Installation directly as ruby gem (dependencies will be installed automatically on your system)
 - Step 1. Install it (it will install automatically dependencies): `gem install evil-winrm`
 - Step 2. Ready. Just launch it! `~$ evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'`
 
### Method 2. Git clone and install dependencies on your system manually
 - Step 1. Install dependencies manually: `~$ sudo gem install winrm winrm-fs stringio`
 - Step 2. Clone the repo: `git clone https://github.com/Hackplayers/evil-winrm.git`
 - Step 3. Ready. Just launch it! `~$ cd evil-winrm && ruby evil-winrm.rb -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'`

### Method 3. Using bundler (dependencies will not be installed on your system, just to use evil-winrm)
 - Step 1. Install bundler: `gem install bundler:2.0.2`
 - Step 2. Install dependencies with bundler: `cd evil-winrm && bundle install --path vendor/bundle`
 - Step 3. Launch it with bundler: `bundle exec evil-winrm.rb -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'`

### Method 4. Using Docker
 - Step 1. Launch docker container based on already built image: `docker run --rm -ti --name evil-winrm -v /home/foo/ps1_scripts:/ps1_scripts -v /home/foo/exe_files:/exe_files -v /home/foo/data:/data oscarakaelvis/evil-winrm -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/ps1_scripts/' -e '/exe_files/'`

## Documentation

#### Clear text password
If you don't want to put the password in clear text, you can optionally avoid to set `-p` argument and the password will be prompted preventing to be shown.

#### Ipv6
To use IPv6, the address must be added to /etc/hosts. Just put the already set name of the host after `-i` argument instead of an IP address.

#### Basic commands
 - **upload**: local files can be auto-completed using tab key. 
   - usage: `upload local_filename` or `upload local_filename destination_filename`
 - **download**: 
   - usage: `download remote_filename` or `download remote_filename destination_filename`

 __Notes about paths (upload/download)__:
   Relative paths are not allowed to use on download/upload. Use filenames on current directory or absolute path.
   If you are using Evil-WinRM in a docker environment, bear in mind that all local paths should be at `/data` and be pretty sure that you mapped it as a volume in order to be able to access to downloaded files or to be able to upload files from your local host O.S.

 - **services**: list all services showing if there your account has permissions over each one. No administrator permissions needed to use this feature.
 - **menu**: load the `Invoke-Binary`, `Dll-Loader`, `Donut-Loader` and `Bypass-4MSI` functions that we will explain below. When a ps1 is loaded all its functions will be shown up.

   ![menu](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image2.png)

#### Load powershell scripts
 - To load a ps1 file you just have to type the name (auto-completion using tab allowed). The scripts must be in the path set at `-s` argument. Type menu again and see the loaded functions. Very large files can take a long time to be loaded.

   ![ps1](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image7.png)

#### Advanced commands
- Invoke-Binary: allows exes compiled from c# to be executed in memory. The name can be auto-completed using tab key. Arguments for the exe file can be passed comma separated. Example: `Invoke-Binary /opt/csharp/Binary.exe 'param1, param2, param3'`. The executables must be in the path set at `-e` argument.

   ![Invoke-Binary](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image3.png)

 - Dll-Loader: allows loading dll libraries in memory, it is equivalent to: `[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("pwn.dll"))`

   The dll file can be hosted by smb, http or locally. Once it is loaded type `menu`, then it is possible to autocomplete all functions.

   ![Dll-Loader1](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image4.png)
   ![Dll-Loader2](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image5.png)

 - Donut-Loader: allows to inject x64 payloads generated with awesome [donut] technique. No need to encode the payload.bin, just generate and inject!

   ![Donut-Loader](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image8.png)

    You can use this [donut-maker] to generate the payload.bin if you don't use Windows.
    This script use a python module written by Marcello Salvati ([byt3bl33d3r]). It could be installed using pip: 

      `pip3 install donut-shellcode`

      ![donuts](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image10.png)

 - Bypass-4MSI: patchs AMSI protection.

      ![amsi](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/resources/image11.png)

#### Kerberos
 - First you have to sync date with the DC: `rdate -n <dc_ip>`

 - To generate ticket there are many ways:

   * Using [ticketer.py] from impacket:

      `ticketer.py -dc-ip <dc_ip> -nthash <krbtgt_nthash> -domain-sid <domain_sid> -domain <domain_name> <user>`

   * If you get a kirbi ticket using [Rubeus] or [Mimikatz] you have to convert to ccache using [ticket_converter.py]:

      `python ticket_converter.py ticket.kirbi ticket.ccache` 

 - Add ccache ticket. There are 2 ways:

    `export KRB5CCNAME=/foo/var/ticket.ccache`

    `cp ticket.ccache /tmp/krb5cc_0`

 - Add realm to `/etc/krb5.conf` (for linux). Use of this format is important:

   ```
    CONTOSO.COM = {
                kdc = fooserver.contoso.com
    }
   ```

 - Check Kerberos tickets with `klist`
 - To remove ticket use: `kdestroy`
 - For more information about Kerberos check this [cheatsheet]

## Changelog:
Changelog and project changes can be checked here: [CHANGELOG.md](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/CHANGELOG.md)

## Credits:
Staff:

 - [Cybervaca], (founder). Twitter: [@CyberVaca_]
 - [OscarAkaElvis], Twitter: [@OscarAkaElvis]
 - [Laox], Twitter: [@_Laox]

Hat tip to:

 - [Vis0r] for his personal support.
 - [Alamot] for his original code.
 - [3v4Si0N] for his awesome dll loader.
 - [WinRb] All contributors of ruby library.
 - [TheWover] for his awesome donut tool.
 - [byt3bl33d3r] for his python library to create donut payloads.
 - [Sh11td0wn] for inspiration about new features.
 - [Hackplayers] for giving a shelter on their github to this software.

## Disclaimer & License
This script is licensed under LGPLv3+. Direct link to [License](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/LICENSE).

Evil-WinRM should be used for authorized penetration testing and/or nonprofit educational purposes only. 
Any misuse of this software will not be the responsibility of the author or of any other collaborator. 
Use it at your own servers and/or with the server owner's permission.

<!-- Github URLs -->
[Cybervaca]: https://github.com/cybervaca
[OscarAkaElvis]: https://github.com/OscarAkaElvis
[Laox]: https://github.com/jarilaos
[Vis0r]: https://github.com/vmotos
[Alamot]: https://github.com/Alamot
[3v4Si0N]: https://github.com/3v4Si0N
[donut]: https://github.com/TheWover/donut
[donut-maker]: https://github.com/Hackplayers/Salsa-tools/blob/master/Donut-Maker/donut-maker.py
[byt3bl33d3r]: https://twitter.com/byt3bl33d3r
[WinRb]: https://github.com/WinRb/WinRM/graphs/contributors
[TheWover]: https://github.com/TheWover
[Sh11td0wn]: https://github.com/Sh11td0wn
[ticketer.py]: https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py
[ticket_converter.py]: https://github.com/Zer1t0/ticket_converter
[Rubeus]: https://github.com/GhostPack/Rubeus
[Mimikatz]: https://github.com/gentilkiwi/mimikatz
[cheatsheet]: https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
[Dockerhub]: https://hub.docker.com/r/oscarakaelvis/evil-winrm
[Hackplayers]: https://www.hackplayers.com/

<!-- Twitter URLs -->
[@CyberVaca_]: https://twitter.com/CyberVaca_
[@OscarAkaElvis]: https://twitter.com/OscarAkaElvis
[@_Laox]: https://twitter.com/_Laox

<!-- Badges URLs -->
[Version-shield]: https://img.shields.io/badge/version-2.3-blue.svg?style=flat-square&colorA=273133&colorB=0093ee "Latest version"
[Ruby2.3-shield]: https://img.shields.io/badge/ruby-2.3%2B-blue.svg?style=flat-square&colorA=273133&colorB=ff0000 "Ruby 2.3 or later"
[License-shield]: https://img.shields.io/badge/license-LGPL%20v3%2B-blue.svg?style=flat-square&colorA=273133&colorB=bd0000 "LGPL v3+"
[Docker-shield]: https://img.shields.io/docker/cloud/automated/oscarakaelvis/evil-winrm.svg?style=flat-square&colorA=273133&colorB=a9a9a9 "Docker rules!"
[Gem-Version]: https://badge.fury.io/rb/evil-winrm.svg "Ruby gem"
