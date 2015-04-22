redis = require('redis')
redis_connection = redis.connect({host: "127.0.0.1", port: 6379})

-- config methods for testing luaoauth1. simple 
local Luaoaauth1TestConfigMethods
Luaoaauth1TestConfigMethods = {
  is_nonce_used: =>
    if redis_connection\get("luaoauth1:nonce_used_false")
      false
    else
      redis_connection\get("luaoauth1:nonces:#{@nonce()}")

  use_nonce: =>
    if redis_connection\get("luaoauth1:nonce_should_not_be_used")
      error("nonce should not have been used")
    set = redis_connection\setnx("luaoauth1:nonces:#{@nonce()}", 'used')
    if not set
      -- checking the same thing as #nonce_used? lets #nonce_used? be overridden to return false and things still work 
      error({type: 'luaoauth1.NonceUsedError'})

  timestamp_valid_period: =>
    10

  allowed_signature_methods: =>
    {'HMAC-SHA1', 'RSA-SHA1', 'PLAINTEXT'}

  consumer_secret: =>
    redis_connection\get("luaoauth1:consumer_secrets:#{@consumer_key()}")

  token_secret: =>
    redis_connection\get("luaoauth1:token_secrets:#{@token()}")

  token_belongs_to_consumer: =>
    redis_connection\get("luaoauth1:token_consumers:#{@token()}") == @consumer_key()

  body_hash_required: =>
    if redis_connection\get("luaoauth1:body_hash_required")
      true
    else
      false
}

TestHelperMethods = require('spec/test_helper_methods')
TestHelperMethods\consumer()
TestHelperMethods\token_hash()

return Luaoaauth1TestConfigMethods
