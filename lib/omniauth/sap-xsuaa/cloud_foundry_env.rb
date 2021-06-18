require 'cf-app-utils'

# Provide ergonomic accessors to XSUAA Service configuration from CloudFoundry's VCAP_SERVICES
#
# See also https://github.com/cloudfoundry/cf-app-utils-ruby
module CloudFoundryEnv
  module Xsuaa
    class MissingVcapServicesError < StandardError; end

    def self.service_name
      ENV.fetch("XSUAA_SERVICE_NAME", "xsuaa")
    end

    # Retrieves the service from VCAP_SERVICES and returns its hash of 'credentials'.
    def self.service
      raise MissingVcapServicesError, "Expected VCAP_SERVICES be present" if ENV['VCAP_SERVICES'].nil?

      @service ||= CF::App::Credentials.find_by_service_name(service_name)
    end

    def self.xsappname
      service['xsappname']
    end

    def self.client_id
      service['clientid']
    end

    def self.client_secret
      service['clientsecret']
    end

    def self.uaa_domain
      service['uaadomain']
    end

    def self.identity_zone
      service['identityzone']
    end

    def self.identity_zone_id
      service['identityzoneid']
    end

    def self.verification_key
      service['verificationkey']
    end

    def self.auth_site_url(tenant)
      "https://#{tenant}.#{uaa_domain}"
    end

    def self.token_url(tenant)
      "#{auth_site_url(tenant)}/oauth/token"
    end
  end
end
