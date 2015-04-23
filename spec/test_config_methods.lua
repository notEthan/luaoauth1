local redis = require('redis')
local redis_connection = redis.connect({
  host = "127.0.0.1",
  port = 6379
})
local Luaoaauth1TestConfigMethods
Luaoaauth1TestConfigMethods = {
  is_nonce_used = function(self)
    if redis_connection:get("luaoauth1:nonce_used_false") then
      return false
    else
      return redis_connection:get("luaoauth1:nonces:" .. tostring(self:nonce()))
    end
  end,
  use_nonce = function(self)
    if redis_connection:get("luaoauth1:nonce_should_not_be_used") then
      error("nonce should not have been used")
    end
    local set = redis_connection:setnx("luaoauth1:nonces:" .. tostring(self:nonce()), 'used')
    if not set then
      return error({
        type = 'luaoauth1.NonceUsedError'
      })
    end
  end,
  timestamp_valid_period = function(self)
    return 10
  end,
  allowed_signature_methods = function(self)
    return {
      'HMAC-SHA1',
      'RSA-SHA1',
      'PLAINTEXT'
    }
  end,
  consumer_secret = function(self)
    return redis_connection:get("luaoauth1:consumer_secrets:" .. tostring(self:consumer_key()))
  end,
  token_secret = function(self)
    return redis_connection:get("luaoauth1:token_secrets:" .. tostring(self:token()))
  end,
  token_belongs_to_consumer = function(self)
    return redis_connection:get("luaoauth1:token_consumers:" .. tostring(self:token())) == self:consumer_key()
  end,
  body_hash_required = function(self)
    if redis_connection:get("luaoauth1:body_hash_required") then
      return true
    else
      return false
    end
  end
}
local TestHelperMethods = require('spec/test_helper_methods')
TestHelperMethods:consumer()
TestHelperMethods:token_hash()
return Luaoaauth1TestConfigMethods
