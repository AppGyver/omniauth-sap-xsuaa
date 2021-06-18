require_relative "lib/omniauth/sap-xsuaa/version"

Gem::Specification.new do |s|
  s.name        = 'omniauth-sap-xsuaa'
  s.version     = OmniAuth::SapXsuaa::VERSION
  s.summary     = "Omniauth Authentication Strategy for SAP XSUAA"
  s.description = "Omniauth Authentication Strategy for SAP XSUAA"
  s.authors     = ["Richard Anderson"]
  s.email       = 'richard.anderson@appgyver.com'
  s.homepage    =
    'https://github.com/AppGyver/omniauth-sap-xsuaa'
  s.license       = 'MIT'

  s.files         = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  s.require_paths = ["lib"]

  s.add_dependency 'omniauth', '~> 2.0'
  s.add_dependency 'omniauth-oauth2'
  s.add_dependency 'jwt'
  s.add_dependency "cf-app-utils", '~> 0.6' # Reads VCAP_SERVICES

  s.add_development_dependency "bundler", "~> 2.0"
end
