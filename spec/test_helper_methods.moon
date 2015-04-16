redis = require('redis')
redis_connection = redis.connect({host: "127.0.0.1", port: 6379})

local TestHelperMethods
TestHelperMethods = {
  consumer: =>
    consumer = {key: "test_client_app_key", secret: "test_client_app_secret"}
    redis_connection\set("luaoauth1:consumer_secrets:#{consumer['key']}", consumer['secret'])
    consumer
  consumer_key: =>
    @consumer()['key']
  consumer_secret: =>
    @consumer()['secret']
  token_hash: =>
    hash = {token: 'test_token', secret: 'test_token_secret', consumer_key: @consumer_key()}
    redis_connection\set("luaoauth1:token_secrets:#{hash['token']}", hash['secret'])
    redis_connection\set("luaoauth1:token_consumers:#{hash['token']}", hash['consumer_key'])
    hash
  token: =>
    @token_hash()['token']
  token_secret: =>
    @token_hash()['secret']
}
return TestHelperMethods
