# Evil-WinRM
The ultimate WinRM shell for hacking/pentesting

```
   ___ __ __  ____  _                  
  /  _]  |  ||    || |                 
 /  [_|  |  | |  | | |                 
|    _]  |  | |  | | |___              
|   [_|  :  | |  | |     |             
|     |\   /  |  | |     |             
|_____| \_/  |____||_____|             
                                       
 __    __  ____  ____   ____   ___ ___ 
|  |__|  ||    ||    \ |    \ |   |   |
|  |  |  | |  | |  _  ||  D  )| _   _ |
|  |  |  | |  | |  |  ||    / |  \_/  |
|  `  '  | |  | |  |  ||    \ |   |   |
 \      /  |  | |  |  ||  .  \|   |   |
  \_/\_/  |____||__|__||__|\_||___|___|
                                       

                           By: CyberVaca@HackPlayers
```

## Description & Purpose
This shell is the ultimate WinRM shell for hacking/pentesting.

WinRM (Windows Remote Management) is the Microsoft implementation of WS-Management Protocol. A standard SOAP based protocol 
that allows hardware and operating systems from different vendors to interoperate. Microsoft included it in their Operating 
Systems in order to make life easier to system adminsitrators.

This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985), of course only 
if you have credentials and permissions to use it. So we can say that it could be used in a post-exploitation hacking/pentesting 
phase. The purpose of this program is to provide nice and easy-to-use features for hacking. It can be used with legitimate 
purposes by system administrators as well but the most of its features are focused on hacking/pentesting stuff.

## Features
 - Command History (pressing up arrow)
 - Command completion (pressing tab)
 - Upload and download files
 - List remote machine services
 - Load Powershell scripts
 - Load dll files in memory
 - Load in memory C# (C Sharp) compiled exe files
 - Colorization on output messages (can be disabled optionally)

## Requirements & Installation
Some ruby gems are needed: `winrm`, `winrm-fs`, `colorize` and `stringio`.

`~$ sudo gem install winrm winrm-fs colorize stringio`

## Quick Start
Step 1. Edit the connection parameters to point correctly to your endpoint and set the right paths to your script and executable files.
Step 2. Ready. Just launch it! `~$ ruby winrm.rb`

Example:
```
# Set the path for your scripts (ps1 files) and your executables (exe files)
$scripts_path = "/home/foo/ps1_scripts/"
$executables_path = "/home/foo/exe_files/"

# Connection parameters, set your ip address or hostname, your user and password
conn = WinRM::Connection.new(
    endpoint: 'http://192.168.1.100:5985/wsman',
    user: 'testdomain\Administrator',
    password: 'MySuperSecr3tPass123!',
    :no_ssl_peer_verification => true,
    # Below, config for SSL, uncomment if needed and set cert files
    # transport: :ssl,
    # client_cert: 'certnew.cer',
    # client_key: 'client.key',
)
```

## Documentation
TODO

## Credits:
Main author:

 - [cybervaca]

Collaborators, documenters, testers and supporters:

 - [OscarAkaElvis]
 - [jarilaos]
 - [vis0r]

Based on the [Alamot]'s original code.

## Disclaimer & License
This script is licensed under GPLv3+. Direct link to [License](LICENSE).

Evil-WinRM should be used for authorized penetration testing and/or nonprofit educational purposes only. 
Any misuse of this software will not be the responsibility of the author or of any other collaborator. 
Use it at your own servers and/or with the server owner's permission.

<!-- Github URLs -->
[cybervaca]: https://github.com/cybervaca
[OscarAkaElvis]: https://github.com/OscarAkaElvis
[jarilaos]: https://github.com/jarilaos
[vis0r]: https://github.com/vmotos
[Alamot]: https://github.com/Alamot
