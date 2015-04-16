-- config methods for testing luaoauth1. simple 

Luaoaauth1TestConfigMethods = {
  -- a set of nonces
  nonces: {}
  -- a Hash keyed by consumer keys with values of consumer secrets
  consumer_secrets: {}
  -- a Hash keyed by tokens with values of token secrets 
  token_secrets: {}
  -- a Hash keyed by tokens with values of consumer keys
  token_consumers: {}

  is_nonce_used: =>
    Luaoaauth1TestConfigMethods.nonces[@nonce()]

  use_nonce: =>
    if Luaoaauth1TestConfigMethods.nonces[@nonce()]
      -- checking the same thing as #nonce_used? lets #nonce_used? be overridden to return false and things still work 
      error({type: 'luaoauth1.NonceUsedError'})
    else
      Luaoaauth1TestConfigMethods.nonces[@nonce()] = true

  timestamp_valid_period: =>
    10

  allowed_signature_methods: =>
    {'HMAC-SHA1', 'RSA-SHA1', 'PLAINTEXT'}

  consumer_secret: =>
    Luaoaauth1TestConfigMethods.consumer_secrets[@consumer_key()]

  token_secret: =>
    Luaoaauth1TestConfigMethods.token_secrets[@token()]

  token_belongs_to_consumer: =>
    Luaoaauth1TestConfigMethods.token_consumers[@token()] == @consumer_key()
}

TestHelperMethods = {
  --simpleapp: =>
  --  proc { |env| [200, {'Content-Type' => 'text/plain; charset=UTF-8'}, ['☺']] } }
  --oapp: =>
  --  Luaoaauth1::RackAuthenticator.new(simpleapp, config_methods: Luaoaauth1TestConfigMethods) }

  consumer: =>
    consumer = {key: "test_client_app_key", secret: "test_client_app_secret"}
    Luaoaauth1TestConfigMethods.consumer_secrets[consumer['key']] = consumer['secret']
    consumer
  consumer_key: =>
    @consumer()['key']
  consumer_secret: =>
    @consumer()['secret']
  token_hash: =>
    hash = {token: 'test_token', secret: 'test_token_secret', consumer_key: consumer_key}
    Luaoaauth1TestConfigMethods.token_secrets[hash['token']] = hash['secret']
    Luaoaauth1TestConfigMethods.token_consumers[hash['token']] = hash['consumer_key']
    hash
  token: =>
    @token_hash()['token']
  token_secret: =>
    @token_hash()['secret']
}
