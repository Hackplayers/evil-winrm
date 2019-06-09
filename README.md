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

## Requirements & Installation
Some ruby gems are needed: `winrm`, `winrm-fs` and `stringio`.

`~$ sudo gem install winrm winrm-fs stringio`

## Documentation
TODO

## Credits:
Main author:

 - [cybervaca]

Collaborators, documenters, testers and supporters:

 - [OscarAkaElvis]
 - [jarilaos]
 - [vis0r]

Based on the [Alamot]'s original code 

## Disclaimer & License

This script is licensed under GPLv3+. Direct link to [License](LICENSE)

Evil-WinRM should be used for authorized penetration testing and/or nonprofit educational purposes only. 
Any misuse of this software will not be the responsibility of the author or of any other collaborator. 
Use it at your own servers and/or with the server owner's permission.

<!-- Github URLs -->
[cybervaca]: https://github.com/cybervaca
[OscarAkaElvis]: https://github.com/OscarAkaElvis
[jarilaos]: https://github.com/jarilaos
[vis0r]: https://github.com/vmotos
[Alamot]: https://github.com/Alamot
