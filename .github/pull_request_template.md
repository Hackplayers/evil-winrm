<!--- Please, before sending a pull request read the Git Workflow Policy on Contributing section of the project -->
<!--- Pull requests to master are not allowed -->
<!--- Write in English only -->
<!--- If the pull request is not matching the policy, it will be closed -->

#### Describe the purpose of the pull request

<!--- Insert answer here -->

Per the requirements, "Evil-WinRM requires version 2.3 or greater". However, in testing with versions 2.7 or greater, I've run into, what is apparently, a pretty common issue with Evil-WinRM erroring out at building the TLS connection with the following error:

└─[$] <> evil-winrm -i 10.129.95.234 -u Administrator -p badminton

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type OpenSSL::Digest::DigestError happened, message is Digest initialization failed: initialization error

Error: Exiting with code 1

After some research, I found that the NixOS team had come across this issue and found a work around. See the following github link: https://github.com/NixOS/nixpkgs/issues/255276.

The solution is to add a file to the /bin directory with the executable and a shell variable to the users config file as follows:
OPENSSL_CONF='/path/to/evil-winrm/bin/evilwinrm-tls.conf

This change enables the software to run on newer versions of the ruby interpreter as seen below.

[micsha@valerie] - [~/.config] - [Tue Feb 27, 18:03]
└─[$] <> asdf current ruby
ruby            3.3.0           /home/micsha/.tool-versions
┌─[micsha@valerie] - [~/.config] - [Tue Feb 27, 18:05]
└─[$] <> print $OPENSSL_CONF
/home/micsha/src/evil-winrm/bin/evilwinrm-tls.conf
┌─[micsha@valerie] - [~/.config] - [Tue Feb 27, 18:08]
└─[$] <> evil-winrm -i 10.129.95.234 -u Administrator -p badminton

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type c:\users\mike\desktop\flag.txt
ea81b7afddd03efaa0945333ed147fac
*Evil-WinRM* PS C:\Users\Administrator\Documents>
