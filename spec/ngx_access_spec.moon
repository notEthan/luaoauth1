describe OAuthenticator::RackAuthenticator, ->
  -- act like a database cleaner
  after do
    [:nonces, :consumer_secrets, :token_secrets, :token_consumers].each do |db|
      OAuthenticatorTestConfigMethods.send(db).clear

  def assert_response(expected_status, expected_body, actual_status, actual_headers, actual_body)
    actual_body_s = actual_body.to_enum.to_a.join
    assert_equal expected_status.to_i, actual_status.to_i, "Expected status to be #{expected_status.inspect}" +
      "; got #{actual_status.inspect}. body was: #{actual_body_s}"
    assert expected_body === actual_body_s, "Expected match for #{expected_body}; got #{actual_body_s}"

  it 'makes a valid two-legged signed request (generated)', ->
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))

  it 'makes a valid two-legged signed request with a blank token (generated)', ->
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => '',
      :token_secret => '',
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))

  it 'makes a valid two-legged signed request with a form encoded body (generated)', ->
    request = Rack::Request.new(Rack::MockRequest.env_for('/',
      :method => 'GET',
      :input => 'a=b&a=c',
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=UTF8'
    ))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))

  it 'makes a valid three-legged signed request (generated)', ->
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
      :request_method => request.request_method,
      :uri => request.url,
      :media_type => request.media_type,
      :body => request.body,
      :signature_method => 'HMAC-SHA1',
      :consumer_key => consumer_key,
      :consumer_secret => consumer_secret,
      :token => token,
      :token_secret => token_secret,
    }).authorization
    assert_response(200, '☺', *oapp.call(request.env))

  2.times do |i|
    -- run these twice to make sure that the databas cleaner clears out the nonce since we use the same 
    -- nonce across tests 
    it "makes a valid signed two-legged request (static #{i})", ->
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
        'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
        'oauth_signature_method="HMAC-SHA1", ' +
        'oauth_timestamp="1391021695", ' +
        'oauth_version="1.0"'
      assert_response(200, '☺', *oapp.call(request.env))

    it "makes a valid signed three-legged request (static #{i})", ->
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      token_hash # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = 'OAuth ' +
        'oauth_consumer_key="test_client_app_key", ' +
        'oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ' +
        'oauth_signature="MyfcvCJfiOHCdkdwFOKtfwoOPqE%3D", ' +
        'oauth_signature_method="HMAC-SHA1", ' +
        'oauth_timestamp="1391021695", ' +
        'oauth_token="test_token", ' +
        'oauth_version="1.0"'
      assert_response(200, '☺', *oapp.call(request.env))

  it 'complains about a missing Authorization header', ->
    assert_response(401, /Authorization header is missing/, *oapp.call({}))

  it 'complains about a blank Authorization header', ->
    assert_response(401, /Authorization header is blank/, *oapp.call({'HTTP_AUTHORIZATION' => ' '}))

  it 'complains about a non-OAuth Authentication header', ->
    assert_response(401, /Authorization scheme is not OAuth/, *oapp.call({'HTTP_AUTHORIZATION' => 'Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='}))

  describe 'invalid Authorization header', ->
    it 'has duplicate params', ->
      assert_response(
        401,
        /Received multiple instances of Authorization parameter oauth_version/,
        *oapp.call({'HTTP_AUTHORIZATION' => 'OAuth oauth_version="1.0", oauth_version="1.1"'})
      )

    it 'has something unparseable', ->
      assert_response(401, /Could not parse Authorization header/, *oapp.call({'HTTP_AUTHORIZATION' => 'OAuth <client-app-key>test_client_app_key</client-app-key>'}))

  it 'omits timestamp', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      --'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_timestamp.*is missing/m, *oapp.call(request.env))
  it 'omits timestamp with PLAINTEXT', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="test_client_app_secret%26", ' +
      'oauth_signature_method="PLAINTEXT", ' +
      --'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(200, '☺', *oapp.call(request.env))
  it 'has a non-integer timestamp', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="now", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_timestamp.*is not an integer - got: now/m, *oapp.call(request.env))
  it 'has a too-old timestamp', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391010893", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_timestamp.*is too old: 1391010893/m, *oapp.call(request.env))
  it 'has a timestamp too far in the future', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391032497", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_timestamp.*is too far in the future: 1391032497/m, *oapp.call(request.env))
  it 'omits version', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="lCVypLHYc6oKz+vOa6DKEivoyys%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695"'
      --'oauth_version="1.0"'
    assert_response(200, '☺', *oapp.call(request.env))
  it 'has a wrong version', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="3.14"'
    assert_response(401, /Authorization oauth_version.*must be 1\.0; got: 3\.14/m, *oapp.call(request.env))
  it 'omits consumer key', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth ' + #'oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_consumer_key.*is missing/m, *oapp.call(request.env))
  it 'has an invalid consumer key', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="nonexistent_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_consumer_key.*is invalid/m, *oapp.call(request.env))
  it 'has an invalid token', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    token_hash # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth ' +
      'oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ' +
      'oauth_signature="MyfcvCJfiOHCdkdwFOKtfwoOPqE%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_token="nonexistent_token", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_token.*is invalid/m, *oapp.call(request.env))
  it 'has a token belonging to a different consumer key', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    token_hash # cause this to be created

    OAuthenticatorTestConfigMethods.consumer_secrets["different_client_app_key"] = "different_client_app_secret"

    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth ' +
      'oauth_consumer_key="different_client_app_key", ' +
      'oauth_nonce="6320851a8f4e18b2ac223497b0477f2e", ' +
      'oauth_signature="PVscPDg%2B%2FjAXRiahIggkeBpN5zI%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_token="test_token", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_token.*does not belong to the specified consumer/m, *oapp.call(request.env))
  it 'omits nonce', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      --'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_nonce.*is missing/m, *oapp.call(request.env))
  it 'omits nonce with PLAINTEXT', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      --'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="test_client_app_secret%26", ' +
      'oauth_signature_method="PLAINTEXT", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(200, '☺', *oapp.call(request.env))
  it 'does not try to use an omitted nonce with PLAINTEXT', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      --'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="test_client_app_secret%26", ' +
      'oauth_signature_method="PLAINTEXT", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    test_config_methods_without_use_nonce = Module.new do
      include OAuthenticatorTestConfigMethods
      def use_nonce!
        raise "#use_nonce! should not have been called"
    app = OAuthenticator::RackAuthenticator.new(simpleapp, :config_methods => test_config_methods_without_use_nonce)
    assert_response(200, '☺', *app.call(request.env))
  it 'has an already-used nonce', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(200, '☺', *oapp.call(request.env))
    assert_response(401, /Authorization oauth_nonce.*has already been used/m, *oapp.call(request.env))
  it 'has an already-used nonce, via use_nonce!', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    test_config_methods_nonce_used_false = Module.new do
      include OAuthenticatorTestConfigMethods
      def nonce_used?
        false
    app = OAuthenticator::RackAuthenticator.new(simpleapp, :config_methods => test_config_methods_nonce_used_false)
    assert_response(200, '☺', *app.call(request.env))
    assert_response(401, /Authorization oauth_nonce.*has already been used/m, *app.call(request.env))
  it 'omits signature', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      --'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_signature.*is missing/m, *oapp.call(request.env))
  it 'omits signature method', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      --'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_signature_method.*is missing/m, *oapp.call(request.env))
  it 'specifies an invalid signature method', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="Xy1s5IUn8x0U2KPyHBw4B2cHZMo%3D", ' +
      'oauth_signature_method="ROT13", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_signature_method.*must be one of HMAC-SHA1, RSA-SHA1, PLAINTEXT; got: ROT13/m, *oapp.call(request.env))
  it 'has an invalid signature', ->
    Timecop.travel Time.at 1391021695
    consumer # cause this to be created
    request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
    request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
      'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
      'oauth_signature="totallylegit", ' +
      'oauth_signature_method="HMAC-SHA1", ' +
      'oauth_timestamp="1391021695", ' +
      'oauth_version="1.0"'
    assert_response(401, /Authorization oauth_signature.*is invalid/m, *oapp.call(request.env))

  describe 'oauth_body_hash', ->
    it 'has a valid body hash', ->
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'text/plain'))
      request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
        'oauth_signature="RkmgdKV4zUPAlY1%2BkjwPSuCSr%2F8%3D", ' +
        'oauth_signature_method="HMAC-SHA1", ' +
        'oauth_timestamp="1391021695", ' +
        'oauth_version="1.0", ' +
        'oauth_body_hash="qvTGHdzF6KLavt4PO0gs2a6pQ00%3D"'
      assert_response(200, '☺', *oapp.call(request.env))

    it 'has an incorrect body hash', ->
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'text/plain'))
      request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
        'oauth_signature="RkmgdKV4zUPAlY1%2BkjwPSuCSr%2F8%3D", ' +
        'oauth_signature_method="HMAC-SHA1", ' +
        'oauth_timestamp="1391021695", ' +
        'oauth_version="1.0", ' +
        'oauth_body_hash="yes this is authentic"'
      assert_response(401, /Authorization oauth_body_hash.*is invalid/m, *oapp.call(request.env))

    it 'has a body hash when one is not allowed (even if it is correct)', ->
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'))
      request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
        'oauth_signature="DG9qcuXaMPMx0fOcVFiUEPdYQnY%3D", ' +
        'oauth_signature_method="HMAC-SHA1", ' +
        'oauth_timestamp="1391021695", ' +
        'oauth_version="1.0", ' +
        'oauth_body_hash="qvTGHdzF6KLavt4PO0gs2a6pQ00%3D"'
      assert_response(401, /Authorization oauth_body_hash.*must not be included with form-encoded requests/m, *oapp.call(request.env))

    it 'has a body hash with PLAINTEXT', ->
      Timecop.travel Time.at 1391021695
      consumer # cause this to be created
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'text/plain'))
      request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
        'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
        'oauth_signature="test_client_app_secret%26", ' +
        'oauth_signature_method="PLAINTEXT", ' +
        'oauth_timestamp="1391021695", ' +
        'oauth_version="1.0", ' +
        'oauth_body_hash="qvTGHdzF6KLavt4PO0gs2a6pQ00%3D"'
      assert_response(200, '☺', *oapp.call(request.env))

    describe 'body hash is required', ->
      let(:hashrequiredapp) do
        hash_required_config = Module.new do
          include OAuthenticatorTestConfigMethods
          define_method(:body_hash_required?) { true }
        OAuthenticator::RackAuthenticator.new(simpleapp, :config_methods => hash_required_config)

      it 'is missing a body hash, one is not allowed', ->
        Timecop.travel Time.at 1391021695
        consumer # cause this to be created
        request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'))
        request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
          'oauth_signature="DG9qcuXaMPMx0fOcVFiUEPdYQnY%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="1391021695", ' +
          'oauth_version="1.0"'
        assert_response(200, '☺', *hashrequiredapp.call(request.env))
      it 'is missing a body hash, one is allowed', ->
        Timecop.travel Time.at 1391021695
        consumer # cause this to be created
        request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'text/plain'))
        request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
          'oauth_signature="czC%2F9Z8tE1H4AJaT8lOKLokrWRE%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="1391021695", ' +
          'oauth_version="1.0"'
        assert_response(401, /Authorization oauth_body_hash.*is required \(on non-form-encoded requests\)/m, *hashrequiredapp.call(request.env))

    describe 'body hash not required', ->
      it 'is missing a body hash, one is not allowed', ->
        Timecop.travel Time.at 1391021695
        consumer # cause this to be created
        request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'))
        request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
          'oauth_signature="DG9qcuXaMPMx0fOcVFiUEPdYQnY%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="1391021695", ' +
          'oauth_version="1.0"'
        assert_response(200, '☺', *oapp.call(request.env))
      it 'is missing a body hash, one is allowed', ->
        Timecop.travel Time.at 1391021695
        consumer # cause this to be created
        request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'PUT', :input => 'hello', 'CONTENT_TYPE' => 'text/plain'))
        request.env['HTTP_AUTHORIZATION'] = 'OAuth oauth_consumer_key="test_client_app_key", ' +
          'oauth_nonce="c1c2bd8676d44e48691c8dceffa66a96", ' +
          'oauth_signature="czC%2F9Z8tE1H4AJaT8lOKLokrWRE%3D", ' +
          'oauth_signature_method="HMAC-SHA1", ' +
          'oauth_timestamp="1391021695", ' +
          'oauth_version="1.0"'
        assert_response(200, '☺', *oapp.call(request.env))

  describe :bypass, ->
    it 'bypasses with invalid request', ->
      oapp = OAuthenticator::RackAuthenticator.new(simpleapp, :bypass => proc { true }, :config_methods => OAuthenticatorTestConfigMethods)
      env = Rack::MockRequest.env_for('/', :method => 'GET').merge({'HTTP_AUTHORIZATION' => 'oauth ?'})
      assert_response(200, '☺', *oapp.call(env))

    it 'does not bypass with invalid request', ->
      oapp = OAuthenticator::RackAuthenticator.new(simpleapp, :bypass => proc { false }, :config_methods => OAuthenticatorTestConfigMethods)
      assert_equal(401, oapp.call({}).first)

    it 'bypasses with valid request', ->
      was_authenticated = nil
      bapp = proc { |env| was_authenticated = env['oauth.authenticated']; [200, {}, ['☺']] }
      boapp = OAuthenticator::RackAuthenticator.new(bapp, :bypass => proc { true }, :config_methods => OAuthenticatorTestConfigMethods)
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
        :request_method => request.request_method,
        :uri => request.url,
        :media_type => request.media_type,
        :body => request.body,
        :signature_method => 'HMAC-SHA1',
        :consumer_key => consumer_key,
        :consumer_secret => consumer_secret
      }).authorization
      assert_response(200, '☺', *boapp.call(request.env))
      assert(was_authenticated == false)

    it 'does not bypass with valid request', ->
      was_authenticated = nil
      bapp = proc { |env| was_authenticated = env['oauth.authenticated']; [200, {}, ['☺']] }
      boapp = OAuthenticator::RackAuthenticator.new(bapp, :bypass => proc { false }, :config_methods => OAuthenticatorTestConfigMethods)
      request = Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET'))
      request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
        :request_method => request.request_method,
        :uri => request.url,
        :media_type => request.media_type,
        :body => request.body,
        :signature_method => 'HMAC-SHA1',
        :consumer_key => consumer_key,
        :consumer_secret => consumer_secret
      }).authorization
      assert_response(200, '☺', *boapp.call(request.env))
      assert(was_authenticated == true)

  describe 'rack env variables', ->
    let :request do
      Rack::Request.new(Rack::MockRequest.env_for('/', :method => 'GET')).tap do |request|
        request.env['HTTP_AUTHORIZATION'] = OAuthenticator::SignableRequest.new({
          :request_method => request.request_method,
          :uri => request.url,
          :media_type => request.media_type,
          :body => request.body,
          :signature_method => 'HMAC-SHA1',
          :consumer_key => consumer_key,
          :consumer_secret => consumer_secret,
          :token => token,
          :token_secret => token_secret,
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
      otestapp = OAuthenticator::RackAuthenticator.new(testapp, :config_methods => OAuthenticatorTestConfigMethods)
      assert_response(200, '☺', *otestapp.call(request.env))
      assert_equal(token, oauth_token)
      assert_equal(consumer_key, oauth_consumer_key)
      assert_equal(true, oauth_authenticated)
