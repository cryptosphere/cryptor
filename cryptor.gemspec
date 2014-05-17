# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'cryptor/version'

Gem::Specification.new do |spec|
  spec.name          = 'cryptor'
  spec.version       = Cryptor::VERSION
  spec.authors       = ['Tony Arcieri']
  spec.email         = ['bascule@gmail.com']
  spec.summary       = 'An easy-to-use library for real-world Ruby cryptography'
  spec.description   = 'A safe Ruby encryption library, designed to support features like' \
                       'multiple active encryption keys and key rotation'
  spec.homepage      = 'https://github.com/cryptosphere/cryptor'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(/^bin\//) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(/^(test|spec|features)\//)
  spec.require_paths = ['lib']

  spec.add_runtime_dependency 'rbnacl-libsodium'

  spec.add_development_dependency 'bundler', '~> 1.6'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'rubocop'
end
