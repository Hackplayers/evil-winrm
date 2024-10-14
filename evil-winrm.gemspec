# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = 'evil-winrm'
  spec.version = '3.7'
  spec.license = 'LGPL-3.0'
  spec.authors = %w[CyberVaca OscarAkaElvis Jarilaos Arale61]
  spec.email = ['oscar.alfonso.diaz@gmail.com']

  spec.summary = 'Evil-WinRM'
  spec.description = 'The ultimate WinRM shell for hacking/pentesting'
  spec.homepage = 'https://github.com/Hackplayers/evil-winrm#readme'
  spec.required_ruby_version = '>= 2.3'

  spec.metadata = {
    'yard.run'              => 'yard',
    'changelog_uri'         => 'https://github.com/Hackplayers/evil-winrm/blob/master/CHANGELOG.md',
    'documentation_uri'     => 'https://rubydoc.info/gems/evil-winrm',
    'homepage_uri'          => spec.homepage,
    'source_code_uri'       => 'https://github.com/Hackplayers/evil-winrm',
    'rubygems_mfa_required' => 'true'
  }

  spec.files = Dir['bin/*'] + ['evil-winrm.rb', 'LICENSE']
  spec.bindir = "bin"
  spec.executables = ["evil-winrm"]

  spec.add_dependency 'fileutils', '~> 1.0'
  spec.add_dependency 'logger',    '~> 1.4', '>= 1.4.3'
  spec.add_dependency 'stringio',  '~> 3.0'
  spec.add_dependency 'winrm',     '~> 2.3', '>= 2.3.7'
  spec.add_dependency 'winrm-fs',  '~> 1.3', '>= 1.3.2'

  spec.add_development_dependency 'bundler', '~> 2.0'

  spec.post_install_message = 'Happy hacking! :)'
end
