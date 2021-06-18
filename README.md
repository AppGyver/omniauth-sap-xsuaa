# OmniAuth Authentication Strategy for SAP XSUAA

## Usage

Define the XSUAA Service Instance's name in an environment variable:

```bash
XSUAA_SERVICE_NAME="xsuaa-example-app"
```

Add omniauth-sap-xsuaa to Gemfile:

```ruby
gem 'omniauth-sap-xsuaa'
```

Configure OmniAuth in `config/initializers/omniauth.rb`

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

## Trying it out locally

Set `VCAP_SERVICES` either with mock values or values from `cf ssh <service-with-xsuaa-binding>`.

For example setting two environment variables such as these allows you to authenticate to the
real authentication provider:

```ruby
ENV['XSUAA_SERVICE_NAME']="xsuaa-example-app"
ENV['VCAP_SERVICES']="{\"xsuaa\":[{
  \"label\": \"xsuaa\",
  \"provider\": null,
  \"plan\": \"application\",
  \"name\": \"xsuaa-example-app\",
  \"tags\": [
    \"xsuaa\"
  ],
  \"instance_guid\": \"5dd76aaf-f937-4544-8e7c-94d911f5abba\",
  \"instance_name\": \"xsuaa-example-app\",
  \"binding_guid\": \"197a4eb1-7bbf-4edb-9bee-2d564816abba\",
  \"binding_name\": null,
  \"credentials\": {
    \"tenantmode\": \"shared\",
    \"sburl\": \"https://internal-xsuaa.authentication.sap.hana.ondemand.com\",
    \"subaccountid\": \"06c0ad74-d224-463c-b46e-5f4d9c4babba\",
    \"credential-type\": \"instance-secret\",
    \"clientid\": \"sb-example-app!t30010\",
    \"xsappname\": \"example-app!t30010\",
    \"clientsecret\": \"verySekritString=\",
    \"url\": \"https://appgyver-int.authentication.sap.hana.ondemand.com\",
    \"uaadomain\": \"authentication.sap.hana.ondemand.com\",
    \"verificationkey\": \"-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4UCgAtdjWTjG6qHjcdobsjk06JsQ6BWd20Q3yutK5n3+e6FCQlpXyBEN0pMIpNjWBx6/85HW/k2vwauwqQCCB4I00HgFXKDjWrktv1eve5MNiWNI1+InXLIQ72gZUVcUi9IjhN/0e/hDcALCIeVNTbW4ZHDqj5wZ5beP/9EzZWYP/sHT1XkWu/8deiT8bq1SysKtYxpt1WG01zqEaSSEOmsZ1tp/gzsbfYTCj+xs10Qmax4TP9AhaAsGY714GAU5w+8Nk2yAfUr+AFn8bQXNK46RwVqI83ZL6N70SiQy02mcsw4VVUaAhB1NnrkCfL2Wrmohw9lQOfEtYBrnoxEMLwIDAQAB-----END PUBLIC KEY-----\",
    \"apiurl\": \"https://api.authentication.sap.hana.ondemand.com\",
    \"identityzone\": \"appgyver-int\",
    \"identityzoneid\": \"20f2417e-38ef-4007-9d66-d990b9c9abba\",
    \"tenantid\": \"20f2417e-38ef-4007-9d66-d990b9c9abba\",
    \"zoneid\": \"20f2417e-38ef-4007-9d66-d990b9c9abba\"
  },
  \"syslog_drain_url\": null,
  \"volume_mounts\": [
  ]
}]}"
```
