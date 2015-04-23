local redis = require('redis')
local redis_connection = redis.connect({
  host = "127.0.0.1",
  port = 6379
})
local TestHelperMethods
TestHelperMethods = {
  consumer = function()
    local consumer = {
      key = "test_client_app_key",
      secret = "test_client_app_secret"
    }
    redis_connection:set("luaoauth1:consumer_secrets:" .. tostring(consumer['key']), consumer['secret'])
    return consumer
  end,
  consumer_key = function()
    return TestHelperMethods.consumer()['key']
  end,
  consumer_secret = function()
    return TestHelperMethods.consumer()['secret']
  end,
  token_hash = function()
    local hash = {
      token = 'test_token',
      secret = 'test_token_secret',
      consumer_key = TestHelperMethods.consumer_key()
    }
    redis_connection:set("luaoauth1:token_secrets:" .. tostring(hash['token']), hash['secret'])
    redis_connection:set("luaoauth1:token_consumers:" .. tostring(hash['token']), hash['consumer_key'])
    return hash
  end,
  token = function()
    return TestHelperMethods.token_hash()['token']
  end,
  token_secret = function()
    return TestHelperMethods.token_hash()['secret']
  end
}
return TestHelperMethods
