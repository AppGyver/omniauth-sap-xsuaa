# OmniAuth Authentication Stragegy for SAP XSUAA

## Usage


```ruby
Rails.application.config.middleware.use OmniAuth::Builder do
  OmniAuth.config.logger = Rails.logger

  provider :sap_xsuaa,
    CloudFoundryEnv::Xsuaa.client_id,
    CloudFoundryEnv::Xsuaa.client_secret,
    uaa_domain: CloudFoundryEnv::Xsuaa.uaa_domain,
    jwt_aud: ['openid', CloudFoundryEnv::Xsuaa.client_id],
    setup: ->(env) do
      tenant = "appgyver-int" # TODO: acquire this dynamically
      env['omniauth.strategy'].options[:client_options][:site] = CloudFoundryEnv::Xsuaa.auth_site_url(tenant)
      env['omniauth.strategy'].options[:token_url] = CloudFoundryEnv::Xsuaa.token_url(tenant)
    end
end
```
