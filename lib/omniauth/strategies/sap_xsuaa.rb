# frozen_string_literal: true

require 'omniauth'
require 'omniauth-oauth2'
require 'multi_json'
require 'net/https'

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
    class FetchJwksError < StandardError; end
    class FetchOpenIdConfigurationError < StandardError; end
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
          name: [first_name, last_name].join(", ")
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
        options[:redirect_uri] || (full_host + callback_path) # + query_string
      end

      private

      def first_name
        jwt_payload['given_name']
      end

      def last_name
        jwt_payload['family_name']
      end

      # SAP JWT Validation:
      # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
      def jwt_options
        {
          verify_iss: true,
          iss: options.token_url,
          verify_iat: true,
          verify_aud: true,
          aud: options.jwt_aud,
          algorithms: ['RS256'],
          jwks: fetch_jwks()
        }
      end

      def jwt_payload
        @jwt_payload ||= parse_jwt
      end

      # Parse the JWT access token
      #
      # Response includes both
      # - "access token" (access_token.token), and
      # - "id token" (access_token.params['id_token']).
      #
      # Both have the same jti token identifier, but only "access token" provides the XSUAA roles
      # and user's real name.
      #
      # Behaviour is inherited from the underlying open source product. It will always
      # additionally issue an OIDC token, but there is currently no supported scenario on BTP
      # with XSUAA OIDC tokens.
      #
      # Hence, the only "access token" is used and "id token" is not read.
      #
      # Example JWT payload:
      #   {"jti"=>"a62729d4d76f4e1c8054919cdfa34630",
      #   "ext_attr"=>
      #     {"enhancer"=>"XSUAA",
      #     "subaccountid"=>"06c0ad74-d224-463c-b46e-5f4d9c4bbcab",
      #     "zdn"=>"appgyver-int"},
      #   "xs.system.attributes"=>
      #     {"xs.rolecollections"=>
      #       ["Destination Administrator",
      #       "Cloud Connector Administrator",
      #       "Subaccount Administrator",
      #       "Connectivity and Destination Administrator"]},
      #   "given_name"=>"Richard",
      #   "family_name"=>"Anderson",
      #   "xs.user.attributes"=>{},
      #   "sub"=>"659444b2-372f-469d-ad9f-493827f759ab",
      #   "user_id"=>"659444b2-372f-469d-ad9f-493827f759ab",
      #   "scope"=>["openid"],
      #   "client_id"=>"sap-auth-playground!t30010",
      #   "cid"=>"sap-auth-playground!t30010",
      #   "azp"=>"sap-auth-playground!t30010",
      #   "grant_type"=>"authorization_code",
      #   "origin"=>"sap.default",
      #   "user_name"=>"richard.anderson@sap.com",
      #   "email"=>"richard.anderson@sap.com",
      #   "auth_time"=>1624011573,
      #   "rev_sig"=>"39022418",
      #   "iat"=>1624012747,
      #   "exp"=>1624617547,
      #   "iss"=> "https://appgyver-int.authentication.sap.hana.ondemand.com/oauth/token",
      #   "zid"=>"20f2417e-38ef-4007-9d66-d990b9c994ab",
      #   "aud"=>["openid", "sap-auth-playground!t30010"]}
      def parse_jwt
        raise MissingAccessTokenError unless access_token&.token
        token = access_token.token

        payload, _header = ::JWT.decode(token, nil, true, jwt_options)

        validate_azp!(payload)
        validate_aud!(payload)

        payload
      end

      # Audience validation
      # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
      #
      # Validation failures:
      # - aud claim AND azp claim are undefined / empty
      # - azp does not match trusted client_id (or xs application id)
      # - OR aud does not contain trusted client_id (or xs application id) provided as part of VCAP_SERVICES.
      #
      # The "aud" attribute is validated by providing "aud" in jwt_options with verify_aud:true
      def validate_azp!(payload)
        azp = payload['azp']

        return if azp && azp == options.client_id

        fail!(
          :invalid_azp,
          CallbackError.new(:invalid_azp, "Expected '#{options.client_id}', received: '#{azp}'")
        )
      end

      # TODO: Validate XSUAA specifics of the audience (pre-defined exact 'aud' is already validated)
      #
      # But in case the scope contains a namespace then the audience contains the namespace as well.
      # For example, this scope xsapp!b4711.namespace.ns.write results in an audience
      # "xsapp!b4711.namespace.ns". That means the audience validator has to trim the namespace(s)
      # before it compares it with the xs application id.
      #
      # Because the client id is added to the list of audiences, you may find client ids of following
      # service instance tokens in the aud similar to "sb-d447781d-c010-4c19-af30-ed49097f22de!b446|xsapp!b4711".
      # In this case the audience matches in case it ends with "|xsapp!b4711".
      def validate_aud!(payload)
        return
      end

      # Fetch one or multiple JWKs which are used for verifying the token signature.
      #
      # The JWK URL should be retrieved from the discovery endpoint.
      # The "same" JWK URL is also present in the JWT Token's Header section, but according to the
      # OIDC specification, "ID tokens SHOULD NOT use the `jku` or `jwk` header parameter fields."
      #
      # In multi tenancy scenarios, the JWKs must be downloaded from an SAP-owned domain
      # and not customer-controlled domains.
      #
      # https://github.wdf.sap.corp/pages/CPSecurity/Knowledge-Base/03_ApplicationSecurity/TokenValidation/
      def fetch_jwks
        jwks_uri = fetch_jwks_uri

        response = Faraday.get(jwks_uri, request_headers)

        unless response.success?
          raise FetchJwksError, "Failed to fetch #{jwks_uri}"
        end

        JSON.parse(response.body, symbolize_names: true)
      end

      def fetch_jwks_uri
        URI(fetch_openid_configuration[:jwks_uri])
      end

      # Authentication endpoint info (tenant specific)
      #
      # https://TENANT.authentication.sap.hana.ondemand.com/.well-known/openid-configuration
      def fetch_openid_configuration
        url = "#{options.client_options.site}/.well-known/openid-configuration"
        response = Faraday.get(url, request_headers)

        unless response.success?
          raise FetchOpenIdConfigurationError, "Failed to fetch #{url}"
        end

        JSON.parse(response.body, symbolize_names: true)
      end

      def request_headers
        {
          'User-Agent' => 'omniauth/sap-xsuaa'
        }
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
