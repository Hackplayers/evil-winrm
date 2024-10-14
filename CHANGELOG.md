### 3.7
 - Fixed menu command to avoid being detected as malware
 - Improved EDR evasion randomizing powershell function names and variables
 - Added progress bar for AMSI bypass

### 3.6
 - Improvements of paths parsing
 - Fixed bug downloading files without extension
 - Replaced deprecated File.exists by File.exist function to avoid errors on newer Ruby versions
 - Added user-agent option (Thanks gmkbenjamin)
 - AMSI bypass refactor
 - ETW bypasss added
 - Fixed Donut-Loader feature

### 3.5
 - Improvements on powershell functions loading
 - Improvements on gemspec file and in ruby code using Rubocop (Thanks noraj)
 - Fixed issues with download and upload commands
 - Added support for simple wildcard usage in upload and download commands
 - Fixed non-controlled error on wrong certificates path when SSL enabled
 - Docker image improved to support remote path completion

### 3.4
 - Added CI files to be used in Github actions for Docker automated building
 - Improvements on dynamic AMSI bypass
 - Added gemspec file to repo for gem building

### 3.3
 - Fixed missing output messages for Invoke-Binary
 - Extracted AMSI bypass from menu to avoid menu problems due to M$ AV signatures
 - Dynamic AMSI bypass implemented to avoid AV signatures

### 3.2
 - Fixed minor duplicated code problem
 - Dockerfile improvements
 - AMSI bypass update

### 3.1
 - Version released just to quick fix ruby dependencies on gem

### 3.0
 - Remote files/directories autocomplete feature
 - Added option to log commands and outputs to a log file (Thanks to Borch Cañavate)

### 2.4
 - File permission access error now handled in exception to avoid losing connection
 - Improvements on bundler installation method
 - Added spn (Service Principal Names) option param for kerberos auth to set some different than default HTTP
 - Fixed prompt colors (ANSI)

### 2.3
 - Fixed Invoke-Binary arguments
 - Service function improved, now show privileges over the services

### 2.2
 - Added progress bar for file uploads/downloads
 - New ascii art on menu
 - Name of Dll loader refactored
 - Help added to Invoke-Binary
 - Fixed Invoke-Binary to accept any number of arguments separated by commas

### 2.1
 - Fixed required params for certificates auth
 - Removed trailing spaces for better visualization
 - Added command line option to disable colors
 - Improved Windows compatibility
 - Trap capturing to avoid accidental shell exit on Ctrl+C

### 2.0
 - Fix GSSAPI error
 - Docker support added

### 1.9
 - Added AMSI bypass
 - Fix the ps1 load with large size
 - Kerberos auth support
 - Improve upload/download functionality

### 1.8
 - Added pass-the-hash feature
 - Added bundler installation method

### 1.7
 - Added x64 compatibility to use Donut payloads

### 1.6
 - Added SSL and certificates support
 - Upload/download messages improved
 - Updated documentation
 - Removed scripts and executables dir as mandatory arguments
 - Added logo

### 1.5
 - Refactor to class
 - Fixed upload/download error
 - Added help arguments for connection

### 1.4
 - Small fixes

### 1.3
 - Added colors to shell prompt
 - Added images to documentation

### 1.2
 - Added some validations
 - Added badges to documentation

### 1.1
 - Translation to english
 - Added first documentation
 - Added colors for messages
 - First ruby gem created

### 1.0
 - Initial commit
