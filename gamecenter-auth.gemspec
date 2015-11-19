# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'gamecenter/auth/version'

Gem::Specification.new do |spec|
  spec.name          = 'gamecenter-auth'
  spec.version       = Gamecenter::Auth::VERSION
  spec.authors       = ['Niklas Bichinger', 'Kai Machemehl']
  spec.email         = %w(niklas@bichinger.de k.machemehl@bichinger.de)

  spec.summary       = %q{Server-side iOS GameKit/Game Center player authentication}
  spec.description   = %q{Server-side iOS GameKit/Game Center player authentication using the "Identity Verification Signature" provided by the method generateIdentityVerificationSignatureWithCompletionHandler in Apple's GameKit framework}
  spec.homepage      = 'https://github.com/bichinger/gamecenter-auth'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.10'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec'
end
