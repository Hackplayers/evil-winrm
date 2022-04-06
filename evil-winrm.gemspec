# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "evil-winrm"
  spec.version = '3.4'
  spec.license = 'LGPL-3.0'
  spec.authors = ["CyberVaca", "OscarAkaElvis", "Jarilaos", "Arale61"]
  spec.email = ["oscar.alfonso.diaz@gmail.com"]

  spec.summary = "Evil-WinRM"
  spec.description = "The ultimate WinRM shell for hacking/pentesting"
  spec.homepage = "https://github.com/Hackplayers/evil-winrm#readme"
  spec.required_ruby_version = ">= 2.3"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/Hackplayers/evil-winrm"
  spec.metadata["changelog_uri"]   = "https://github.com/Hackplayers/evil-winrm/blob/master/CHANGELOG.md"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject do |f|
      (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
    end
  end
  spec.bindir = "bin"
  spec.executables = ["evil-winrm"]

  spec.add_dependency "winrm",     "~> 2.3", ">= 2.3.2"
  spec.add_dependency "winrm-fs",  "~> 1.3", ">= 1.3.2"
  spec.add_dependency "stringio",  "~> 3.0"
  spec.add_dependency "logger",    "~> 1.4", ">= 1.4.3"
  spec.add_dependency "fileutils", "~> 1.0"

  spec.add_development_dependency "bundler", "~> 2.0"

  spec.post_install_message = "Happy hacking! :)"
end
