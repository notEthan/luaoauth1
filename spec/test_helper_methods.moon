return {
  consumer: =>
    consumer = {key: "test_client_app_key", secret: "test_client_app_secret"}
    Luaoaauth1TestConfigMethods.consumer_secrets[consumer['key']] = consumer['secret']
    consumer
  consumer_key: =>
    @consumer()['key']
  consumer_secret: =>
    @consumer()['secret']
  token_hash: =>
    hash = {token: 'test_token', secret: 'test_token_secret', consumer_key: @consumer_key()}
    Luaoaauth1TestConfigMethods.token_secrets[hash['token']] = hash['secret']
    Luaoaauth1TestConfigMethods.token_consumers[hash['token']] = hash['consumer_key']
    hash
  token: =>
    @token_hash()['token']
  token_secret: =>
    @token_hash()['secret']
}
