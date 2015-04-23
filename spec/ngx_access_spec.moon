spec_server = require("lapis.spec.server")
request = spec_server.request
luaoauth1 = require('luaoauth1')
SignableRequest = require('luaoauth1.signable_request')
redis = require('redis')
redis_connection = redis.connect({host: "127.0.0.1", port: 6379})
local app_port

real_os_time = os.time
redis_connection = require('redis').connect({host: "localhost", port: 6379})
os.time = ->
  tonumber(redis_connection\get('luaoauth1:os_time')) or real_os_time()
set_os_time = (time) ->
  redis_connection\set('luaoauth1:os_time', time)

describe 'ngx_access', ->
  setup ->
    spec_server.load_test_server()
    -- the specs need the port to be 80 but I don't see a way to make the spec server choose this port. 
    -- instead it's hardcoded in nginx.conf and here.
    --app_port = spec_server.get_current_server().app_port
    spec_server.get_current_server().app_port = 80
    app_port = 80
  teardown ->
    spec_server.close_test_server()

  -- act like a database cleaner
  after_each ->
    redis_connection\del('luaoauth1:os_time')
    redis_connection\del("luaoauth1:nonce_should_not_be_used")
    redis_connection\del("luaoauth1:nonce_used_false")
    redis_connection\del("luaoauth1:body_hash_required")
    for db in *{'nonces', 'consumer_secrets', 'token_secrets', 'token_consumers'}
      --cursor = false
      --while cursor != 0
        --cursor, keys = unpack(redis_connection\scan(cursor or 0, {match: "luaoauth1:#{db}:*"}))
      do
        keys = redis_connection\keys("luaoauth1:#{db}:*")
        for key in *keys
          redis_connection\del(key)

  TestHelperMethods = require('spec/test_helper_methods')
  import consumer, consumer_key, consumer_secret, token_hash, token, token_secret from TestHelperMethods

  assert_response = (expected_status, expected_body, actual_status, actual_body, actual_headers) ->
    assert.same expected_status, actual_status
    unless string.find(actual_body, expected_body)
      error("expected #{actual_body} to contain #{expected_body}")

  it 'makes a valid two-legged signed request (generated)', ->
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = SignableRequest({
      request_method: request_table.method,
      uri: {scheme: 'http', host: 'example.org', port: app_port, request_uri: '/'},
      media_type: false,
      body: false,
      signature_method: 'HMAC-SHA1',
      consumer_key: consumer_key(),
      consumer_secret: consumer_secret(),
    })\authorization()
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)

  it 'makes a valid two-legged signed request with a blank token (generated)', ->
    request_uri = '/'
    request_table = {headers: {}, method: 'GET'}
    request_table.headers['Authorization'] = SignableRequest({
      request_method: request_table.method,
      uri: {scheme: 'http', host: '127.0.0.1', port: app_port, request_uri: request_uri},
      media_type: false,
      body: false,
      signature_method: 'HMAC-SHA1',
      consumer_key: consumer_key(),
      consumer_secret: consumer_secret(),
      token: '',
      token_secret: '',
    })\authorization()
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)

  it 'makes a valid two-legged signed request with a form encoded body (generated)', ->
    request_uri = '/'
    request_table = {
      headers: {'Content-type': 'application/x-www-form-urlencoded; charset=UTF8'},
      method: 'GET',
      data: 'a=b&a=c'
    }
    request_table.headers['Authorization'] = SignableRequest({
      request_method: request_table.method,
      uri: {scheme: 'http', host: '127.0.0.1', port: app_port, request_uri: request_uri},
      media_type: 'application/x-www-form-urlencoded',
      body: request_table.data,
      signature_method: 'HMAC-SHA1',
      consumer_key: consumer_key(),
      consumer_secret: consumer_secret()
    })\authorization()
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)

  it 'makes a valid three-legged signed request (generated)', ->
    request_uri = '/'
    request_table = {
      headers: {'Content-type': 'application/x-www-form-urlencoded; charset=UTF8'},
      method: 'GET',
      data: 'a=b&a=c'
    }
    request_table.headers['Authorization'] = SignableRequest({
      request_method: request_table.method,
      uri: {scheme: 'http', host: '127.0.0.1', port: app_port, request_uri: request_uri},
      media_type: 'application/x-www-form-urlencoded',
      body: request_table.data,
      signature_method: 'HMAC-SHA1',
      consumer_key: consumer_key(),
      consumer_secret: consumer_secret()
      token: token(),
      token_secret: token_secret(),
    })\authorization()
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)

  for i = 1, 2
    -- run these twice to make sure that the database cleaner clears out the nonce since we use the same 
    -- nonce across tests 
    it "makes a valid signed two-legged request (static #{i})", ->
      set_os_time(1391021695)
      consumer() -- cause this to be created
      request_uri = 'http://example.org/'
      request_table = {
        headers: {},
        method: 'GET',
      }
      request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
        'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
        'oauth_signature_method="HMAC-SHA1", ' ..
        'oauth_timestamp="1391021695", ' ..
        'oauth_version="1.0"'
      status, body, headers = request(request_uri, request_table)
      assert_response(200, '☺', status, body, headers)

    it "makes a valid signed three-legged request (static #{i})", ->
      set_os_time(1391021695)
      consumer() -- cause this to be created
      token_hash() -- cause this to be created
      request_uri = 'http://example.org/'
      request_table = {
        headers: {},
        method: 'GET',
      }
      request_table.headers['Authorization'] = 'OAuth ' ..
        'oauth_consumer_key="test_client_app_key", ' ..
        'oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ' ..
        'oauth_signature="MyfcvCJfiOHCdkdwFOKtfwoOPqE%3D", ' ..
        'oauth_signature_method="HMAC-SHA1", ' ..
        'oauth_timestamp="1391021695", ' ..
        'oauth_token="test_token", ' ..
        'oauth_version="1.0"'
      status, body, headers = request(request_uri, request_table)
      assert_response(200, '☺', status, body, headers)

  it 'complains about a missing Authorization header', ->
    status, body, headers = request('/', {})
    assert_response(401, 'Authorization header is missing', status, body, headers)

  it 'complains about a blank Authorization header', ->
    status, body, headers = request('/', {headers: {Authorization: ' '}})
    assert_response(401, 'Authorization header is blank', status, body, headers)

  it 'complains about a non-OAuth Authentication header', ->
    status, body, headers = request('/', {headers: {Authorization: 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='}})
    assert_response(401, 'Could not parse Authorization header', status, body, headers)

  describe 'invalid Authorization header', ->
    it 'has duplicate params', ->
      status, body, headers = request('/', {headers: {Authorization: 'OAuth oauth_version="1.0", oauth_version="1.1"'}})
      assert_response(401, 'Received duplicate parameters: oauth_version', status, body, headers)

    it 'has something unparseable', ->
      status, body, headers = request('/', {headers: {Authorization: 'OAuth <client-app-key>test_client_app_key</client-app-key>'}})
      assert_response(401, 'Could not parse Authorization header', status, body, headers)

  it 'omits timestamp', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      --'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_timestamp.*is missing', status, body, headers)
  it 'omits timestamp with PLAINTEXT', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="test_client_app_secret%26", ' ..
      'oauth_signature_method="PLAINTEXT", ' ..
      --'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)
  it 'has a non-integer timestamp', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="now", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_timestamp.*is not an integer %- got: now', status, body, headers)
  it 'has a too-old timestamp', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391010893", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_timestamp.*is too old: 1391010893', status, body, headers)
  it 'has a timestamp too far in the future', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391032497", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_timestamp.*is too far in the future: 1391032497', status, body, headers)
  it 'omits version #this', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="lCVypLHYc6oKz+vOa6DKEivoyys%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695"'
      --'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)
  it 'has a wrong version', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="3.14"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_version.*must be 1\.0; got: 3\.14', status, body, headers)
  it 'omits consumer key', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth ' .. #'oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_consumer_key.*is missing', status, body, headers)
  it 'has an invalid consumer key', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="nonexistent_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_consumer_key.*is invalid', status, body, headers)
  it 'has an invalid token', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    token_hash() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth ' ..
      'oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ' ..
      'oauth_signature="MyfcvCJfiOHCdkdwFOKtfwoOPqE%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_token="nonexistent_token", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_token.*is invalid', status, body, headers)
  it 'has a token belonging to a different consumer key', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    token_hash() -- cause this to be created

    redis_connection\set("luaoauth1:consumer_secrets:different_client_app_key", "different_client_app_secret")

    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth ' ..
      'oauth_consumer_key="different_client_app_key", ' ..
      'oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ' ..
      'oauth_signature="PVscPDg%2B%2FjAXRiahIggkeBpN5zI%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_token="test_token", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_token.*does not belong to the specified consumer', status, body, headers)
  it 'omits nonce', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      --'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_nonce.*is missing', status, body, headers)
  it 'omits nonce with PLAINTEXT', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      --'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="test_client_app_secret%26", ' ..
      'oauth_signature_method="PLAINTEXT", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)
  it 'does not try to use an omitted nonce with PLAINTEXT', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      --'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="test_client_app_secret%26", ' ..
      'oauth_signature_method="PLAINTEXT", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    redis_connection\set("luaoauth1:nonce_should_not_be_used", '1')
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)
  it 'has an already-used nonce', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_nonce.*has already been used', status, body, headers)
  it 'has an already-used nonce, via use_nonce!', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    redis_connection\set("luaoauth1:nonce_used_false", '1')
    status, body, headers = request(request_uri, request_table)
    assert_response(200, '☺', status, body, headers)
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_nonce.*has already been used', status, body, headers)
  it 'omits signature', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      --'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_signature.*is missing', status, body, headers)
  it 'omits signature method', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      --'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_signature_method.*is missing', status, body, headers)
  it 'specifies an invalid signature method', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' ..
      'oauth_signature_method="ROT13", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_signature_method must be one of HMAC%-SHA1, RSA%-SHA1, PLAINTEXT; got: ROT13', status, body, headers)
  it 'has an invalid signature', ->
    set_os_time(1391021695)
    consumer() -- cause this to be created
    request_uri = 'http://example.org/'
    request_table = {
      headers: {},
      method: 'GET',
    }
    request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
      'oauth_signature="totallylegit", ' ..
      'oauth_signature_method="HMAC-SHA1", ' ..
      'oauth_timestamp="1391021695", ' ..
      'oauth_version="1.0"'
    status, body, headers = request(request_uri, request_table)
    assert_response(401, 'Authorization oauth_signature.*is invalid', status, body, headers)

  describe 'oauth_body_hash', ->
    it 'has a valid body hash', ->
      set_os_time(1391021695)
      consumer() -- cause this to be created
      request_uri = 'http://example.org/'
      request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'text/plain'}}
      request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
        'oauth_signature="RkmgdKV4zUPAlY1%2BkjwPSuCSr%2F8%3D", ' ..
        'oauth_signature_method="HMAC-SHA1", ' ..
        'oauth_timestamp="1391021695", ' ..
        'oauth_version="1.0", ' ..
        'oauth_body_hash="qvTGHdzF6KLavt4PO0gs2a6pQ00%3D"'
      status, body, headers = request(request_uri, request_table)
      assert_response(200, '☺', status, body, headers)

    it 'has an incorrect body hash', ->
      set_os_time(1391021695)
      consumer() -- cause this to be created
      request_uri = 'http://example.org/'
      request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'text/plain'}}
      request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
        'oauth_signature="RkmgdKV4zUPAlY1%2BkjwPSuCSr%2F8%3D", ' ..
        'oauth_signature_method="HMAC-SHA1", ' ..
        'oauth_timestamp="1391021695", ' ..
        'oauth_version="1.0", ' ..
        'oauth_body_hash="yes this is authentic"'
      status, body, headers = request(request_uri, request_table)
      assert_response(401, 'Authorization oauth_body_hash.*is invalid', status, body, headers)

    it 'has a body hash when one is not allowed (even if it is correct)', ->
      set_os_time(1391021695)
      consumer() -- cause this to be created
      request_uri = 'http://example.org/'
      request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'application/x-www-form-urlencoded'}}
      request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
        'oauth_signature="DG9qcuXaMPMx0fOcVFiUEPdYQnY%3D", ' ..
        'oauth_signature_method="HMAC-SHA1", ' ..
        'oauth_timestamp="1391021695", ' ..
        'oauth_version="1.0", ' ..
        'oauth_body_hash="qvTGHdzF6KLavt4PO0gs2a6pQ00%3D"'
      status, body, headers = request(request_uri, request_table)
      assert_response(401, 'Authorization oauth_body_hash.*must not be included with form%-encoded requests', status, body, headers)

    it 'has a body hash with PLAINTEXT', ->
      set_os_time(1391021695)
      consumer() -- cause this to be created
      request_uri = 'http://example.org/'
      request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'text/plain'}}
      request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
        'oauth_signature="test_client_app_secret%26", ' ..
        'oauth_signature_method="PLAINTEXT", ' ..
        'oauth_timestamp="1391021695", ' ..
        'oauth_version="1.0", ' ..
        'oauth_body_hash="qvTGHdzF6KLavt4PO0gs2a6pQ00%3D"'
      status, body, headers = request(request_uri, request_table)
      assert_response(200, '☺', status, body, headers)

    describe 'body hash is required', ->
      it 'is missing a body hash, one is not allowed', ->
        set_os_time(1391021695)
        consumer() -- cause this to be created
        request_uri = 'http://example.org/'
        request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'application/x-www-form-urlencoded'}}
        request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
          'oauth_signature="DG9qcuXaMPMx0fOcVFiUEPdYQnY%3D", ' ..
          'oauth_signature_method="HMAC-SHA1", ' ..
          'oauth_timestamp="1391021695", ' ..
          'oauth_version="1.0"'
        redis_connection\set("luaoauth1:body_hash_required", 1)
        status, body, headers = request(request_uri, request_table)
        assert_response(200, '☺', status, body, headers)
      it 'is missing a body hash, one is allowed', ->
        set_os_time(1391021695)
        consumer() -- cause this to be created
        request_uri = 'http://example.org/'
        request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'text/plain'}}
        request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
          'oauth_signature="czC%2F9Z8tE1H4AJaT8lOKLokrWRE%3D", ' ..
          'oauth_signature_method="HMAC-SHA1", ' ..
          'oauth_timestamp="1391021695", ' ..
          'oauth_version="1.0"'
        redis_connection\set("luaoauth1:body_hash_required", 1)
        status, body, headers = request(request_uri, request_table)
        assert_response(401, 'Authorization oauth_body_hash.*is required %(on non%-form%-encoded requests%)', status, body, headers)

    describe 'body hash not required', ->
      it 'is missing a body hash, one is not allowed', ->
        set_os_time(1391021695)
        consumer() -- cause this to be created
        request_uri = 'http://example.org/'
        request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'application/x-www-form-urlencoded'}}
        request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
          'oauth_signature="DG9qcuXaMPMx0fOcVFiUEPdYQnY%3D", ' ..
          'oauth_signature_method="HMAC-SHA1", ' ..
          'oauth_timestamp="1391021695", ' ..
          'oauth_version="1.0"'
        status, body, headers = request(request_uri, request_table)
        assert_response(200, '☺', status, body, headers)
      it 'is missing a body hash, one is allowed', ->
        set_os_time(1391021695)
        consumer() -- cause this to be created
        request_uri = 'http://example.org/'
        request_table = {method: 'PUT', data: 'hello', headers: {'Content-Type': 'text/plain'}}
        request_table.headers['Authorization'] = 'OAuth oauth_consumer_key="test_client_app_key", ' ..
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' ..
          'oauth_signature="czC%2F9Z8tE1H4AJaT8lOKLokrWRE%3D", ' ..
          'oauth_signature_method="HMAC-SHA1", ' ..
          'oauth_timestamp="1391021695", ' ..
          'oauth_version="1.0"'
        status, body, headers = request(request_uri, request_table)
        assert_response(200, '☺', status, body, headers)
[==[
  describe :bypass, ->
    it 'bypasses with invalid request', ->
      oapp = Luaoaauth1::RackAuthenticator.new(simpleapp, bypass: proc { true }, config_methods: Luaoaauth1TestConfigMethods)
      env = Rack::MockRequest.env_for('/', method: 'GET').merge({HTTP_AUTHORIZATION: 'oauth ?'})
      assert_response(200, '☺', *oapp.call(env))

    it 'does not bypass with invalid request', ->
      oapp = Luaoaauth1::RackAuthenticator.new(simpleapp, bypass: proc { false }, config_methods: Luaoaauth1TestConfigMethods)
      assert_equal(401, oapp.call({}).first)

    it 'bypasses with valid request', ->
      was_authenticated = nil
      bapp = proc { |env| was_authenticated = env['oauth.authenticated']; [200, {}, ['☺']] }
      boapp = Luaoaauth1::RackAuthenticator.new(bapp, bypass: proc { true }, config_methods: Luaoaauth1TestConfigMethods)
      request_uri = 'http://example.org/'
      request_table = {
        headers: {},
        method: 'GET',
      }
      request_table.headers['Authorization'] = Luaoaauth1::SignableRequest.new({
        request_method: request.request_method,
        uri: request.url,
        media_type: request.media_type,
        body: request.body,
        signature_method: 'HMAC-SHA1',
        consumer_key: consumer_key,
        consumer_secret: consumer_secret
      }).authorization
      status, body, headers = request(request_uri, request_table)
      assert_response(200, '☺', *boapp.call(request.env))
      assert(was_authenticated == false)

    it 'does not bypass with valid request', ->
      was_authenticated = nil
      bapp = proc { |env| was_authenticated = env['oauth.authenticated']; [200, {}, ['☺']] }
      boapp = Luaoaauth1::RackAuthenticator.new(bapp, bypass: proc { false }, config_methods: Luaoaauth1TestConfigMethods)
      request_uri = 'http://example.org/'
      request_table = {
        headers: {},
        method: 'GET',
      }
      request_table.headers['Authorization'] = Luaoaauth1::SignableRequest.new({
        request_method: request.request_method,
        uri: request.url,
        media_type: request.media_type,
        body: request.body,
        signature_method: 'HMAC-SHA1',
        consumer_key: consumer_key,
        consumer_secret: consumer_secret
      }).authorization
      status, body, headers = request(request_uri, request_table)
      assert_response(200, '☺', *boapp.call(request.env))
      assert(was_authenticated == true)

  describe 'rack env variables', ->
    let :request do
      Rack::Request.new(Rack::MockRequest.env_for('/', method: 'GET')).tap do |request|
        request_table.headers['Authorization'] = Luaoaauth1::SignableRequest.new({
          request_method: request.request_method,
          uri: request.url,
          media_type: request.media_type,
          body: request.body,
          signature_method: 'HMAC-SHA1',
          consumer_key: consumer_key,
          consumer_secret: consumer_secret,
          token: token,
          token_secret: token_secret,
        }).authorization

    it 'sets oauth.authenticated, oauth.token, oauth.consumer_key', ->
      oauth_authenticated = nil
      oauth_token = nil
      oauth_consumer_key = nil
      testapp = proc do |env|
        oauth_authenticated = env['oauth.authenticated']
        oauth_token = env['oauth.token']
        oauth_consumer_key = env['oauth.consumer_key']
        [200, {}, ['☺']]
      otestapp = Luaoaauth1::RackAuthenticator.new(testapp, config_methods: Luaoaauth1TestConfigMethods)
      assert_response(200, '☺', *otestapp.call(request.env))
      assert_equal(token, oauth_token)
      assert_equal(consumer_key, oauth_consumer_key)
      assert_equal(true, oauth_authenticated)
]==]
