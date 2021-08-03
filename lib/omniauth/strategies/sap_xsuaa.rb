# frozen_string_literal: true

require 'omniauth'
require 'omniauth-oauth2'
require "sap/jwt"

# Omniauth Auth Hash Schema doucmentation
# https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
#
# Managing multiple providers
# https://github.com/omniauth/omniauth/wiki/Managing-Multiple-Providers
#
# Devise > config/initiailzers/devise.rb
#   require "strategies/my_strategy"
#   Devise.setup do
#     config.omniauth :my_service, :strategy_class => Strategies::MyStrategy
#   end
#
# Only POST requests to /:provider/auth are allowed since OmniAuth 2
# See also: https://github.com/omniauth/omniauth/wiki/Resolving-CVE-2015-9284
module OmniAuth
  # https://github.com/omniauth/omniauth/blob/master/lib/omniauth/strategy.rb
  module Strategies
    class MissingAccessTokenError < StandardError; end

    class SapXsuaa < OmniAuth::Strategies::OAuth2
      include OmniAuth::Strategy

      option :name, 'xsuaa'
      option :client_id
      option :client_secret
      option :provider_ignores_state, false

      option :uaa_domain, 'missing_option_uaa_domain'
      option :jwt_aud, 'missing_option_jwd_aud'
      option :token_url, 'missing_option_token_url'

      # XSUAA options
      # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/Syntax%20and%20Semantics%20of%20xs-security.json/
      #
      # site: https://tenant.uaadomain/endpoint
      # subdomain - tenant's subdomain (zdn), defined dynamically at OmniAuth's request phase
      # uaadomain - VCAP_SERVICES > xsuaa.credentials.uaadomain
      # endpoint  - /oauth/token
      option :client_options, {
        site: 'site_provided_dynamically_at_request_phase',
        authorize_url: '/oauth/authorize',
        token_url: '/oauth/token'
      }

      uid { jwt_payload['sub'] }

      # User information according to the OmniAuth Auth Hash Schema
      #
      # https://github.com/omniauth/omniauth/wiki/Auth-Hash-Schema
      info do
        prune!(
          email: jwt_payload['email'],
          first_name: first_name,
          last_name: last_name,
          name: [first_name, last_name].join(" ")
        )
      end

      # Extract user's credentials from the JWT token
      credentials do
        prune!(
          token: access_token.token,
          refresh_token: access_token.refresh_token,
          expires: true,
          expires_at: access_token.expires_at
        )
      end

      # Provider specific information about the User and their Tenant.
      extra do
        prune!(
          sub: jwt_payload['sub'],
          jti: jwt_payload['jti'],
          zid: jwt_payload['zid'],
          origin: jwt_payload['origin'],
          ext_attr: jwt_payload['ext_attr'],
          "xs.system.attributes": jwt_payload['xs.system.attributes'],
          "xs.user.attributes": jwt_payload['xs.user.attributes']
        )
      end

      # https://github.com/omniauth/omniauth/blob/a62d36b3f847e0e55b077790112e96950c35085a/lib/omniauth/strategy.rb#L496
      def callback_url
        full_host + callback_path
      end

      private

      def first_name
        jwt_payload['given_name']
      end

      def last_name
        jwt_payload['family_name']
      end

      def jwt_payload
        @jwt_payload ||= verify_jwt!
      end

      # SAP JWT Validation:
      # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
      def verify_jwt!
        raise MissingAccessTokenError unless access_token&.token
        token = access_token.token

        oidc_config = Sap::Jwt.fetch_openid_configuration("#{options.client_options.site}/.well-known/openid-configuration")
        jwks = Sap::Jwt.fetch_jwks(oidc_config[:jwks_uri])

        payload, _header = Sap::Jwt.verify!(
          token,
          client_id: options.client_id,
          iss: options.token_url,
          aud: options.jwt_aud,
          jwks: jwks,
          verify_iss: true,
          verify_iat: true,
          verify_aud: true,
          algorithms: ['RS256'],
        )

        payload
      end

      # Remove empty elements from a hash
      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end
    end
  end
end
