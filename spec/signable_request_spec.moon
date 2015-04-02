SignableRequest = require('luaoauth1/signable_request')

merge = (a, b) ->
  out = {}
  out[k] = v for k, v in pairs(a)
  out[k] = v for k, v in pairs(b)
  out
has_key = (table, testkey) ->
  out = false
  out = true for key, _ in pairs(table) when testkey == key
  out

describe 'signable_request', ->
  base_example_initialize_attrs = ->
    {
      request_method: 'get',
      --uri: 'http://example.com',
      uri: {scheme: 'http', host: 'example.com', port: 80, request_uri: '/'},
      media_type: 'text/plain',
      body: 'hi there',
    }
  example_initialize_attrs = ->
    merge(base_example_initialize_attrs(), {
      consumer_key: 'a consumer key',
      consumer_secret: 'a consumer secret',
      signature_method: 'PLAINTEXT'
    })

  example_request = (attributes={}) ->
    SignableRequest(merge(example_initialize_attrs(), attributes))

  example_signed_request = (authorization, attributes={}) ->
    attributes = merge(attributes, {authorization: authorization})
    SignableRequest(merge(base_example_initialize_attrs(), attributes))

  rsa_private_key = ->
    "-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY"

  describe 'initialize', ->
    describe 'default attributes', ->
      describe 'with any signature method', ->
        for signature_method, _ in pairs(SignableRequest.SIGNATURE_METHODS)
          it "defaults to version 1.0 with #{signature_method}", ->
            request = example_request({signature_method: signature_method})
            assert.same('1.0', request\protocol_params()['oauth_version'])
          it "lets you omit version if you really want to with #{signature_method}", ->
            request = example_request({version: false, signature_method: signature_method})
            assert.same nil, request\protocol_params()['oauth_version']
      describe 'not plaintext', ->
        it 'generates nonces', ->
          nonce1 = example_request({signature_method: 'HMAC-SHA1'})\protocol_params()['oauth_nonce']
          nonce2 = example_request({signature_method: 'HMAC-SHA1'})\protocol_params()['oauth_nonce']
          assert.truthy nonce1
          assert.truthy nonce2
          assert.is_not.same nonce1, nonce2
        it 'generates timestamp', ->
          time = os.time()
          request = example_request({signature_method: 'HMAC-SHA1'})
          assert.same tostring(time), request\protocol_params()['oauth_timestamp']
      describe 'plaintext', ->
        it 'does not generate nonces', ->
          request = example_request({signature_method: 'PLAINTEXT'})
          assert.is_false has_key(request\protocol_params(), 'oauth_nonce')
        it 'does not generate timestamp', ->
          request = example_request({signature_method: 'PLAINTEXT'})
          assert.is_false(has_key(request\protocol_params(), 'oauth_timestamp'))

    it 'checks type', ->
      assert.has_error, -> SignableRequest("hello!")

    it 'checks authorization type', ->
      assert.has_error, -> example_request({authorization: "hello!"})

    it 'does not allow protocol parameters to be specified when authorization is specified', ->
      for key, _ in pairs(SignableRequest.PROTOCOL_PARAM_KEYS)
        assert.has_error, ->
          example_signed_request({}, [key]: 'val')

    describe 'required attributes', ->
      it 'complains about missing required params', ->
        _, err = pcall -> SignableRequest({})
        for required in *{'request_method', 'uri', 'media_type', 'body', 'consumer_key', 'signature_method'}
          assert.is_truthy string.find(err, required, 1, true)

  describe 'the example in 3.1', ->
    -- a request with attributes from the oauth spec
    spec_request = (attributes={}) ->
      example_request({
        request_method: 'POST',
        --uri: 'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b',
        uri: {scheme: 'http', host: 'example.com', port: 80, request_uri: '/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b'},
        media_type: 'application/x-www-form-urlencoded',
        body: 'c2&a3=2+q',
        consumer_key: '9djdj82h48djs9d2',
        token: 'kkk9d7dh3k39sjv7',
        consumer_secret: 'j49sk3j29djd',
        token_secret: 'dh893hdasih9',
        signature_method: 'HMAC-SHA1',
        timestamp: '137131201',
        nonce: '7d8f3e4a',
        version: false,
        realm: "Example",
      })

    it 'has the same signature base string', ->
      spec_signature_base = (
        "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q" ..
        "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_" ..
        "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m" ..
        "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk" ..
        "9d7dh3k39sjv7"
      )
      assert.same(spec_signature_base, spec_request()\signature_base())

    it 'has the same normalized parameters', ->
      spec_normalized_request_params_string = (
        "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj" ..
        "dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1" ..
        "&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
      )
      assert.same(spec_normalized_request_params_string, spec_request()\normalized_request_params_string())

    it 'calculates authorization the same', ->
      -- a keen observer may note that the signature is different than the one in the actual spec. the spec is
      -- in error - see http://www.rfc-editor.org/errata_search.php?rfc=5849
      spec_authorization = OAuthenticator.parse_authorization('OAuth realm="Example",
        oauth_consumer_key="9djdj82h48djs9d2",
        oauth_token="kkk9d7dh3k39sjv7",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131201",
        oauth_nonce="7d8f3e4a",
        oauth_signature="r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D"
      ')
      assert_equal(spec_authorization, spec_request.signed_protocol_params)

  describe '#authorization', ->
    it 'has the parameter name followed by an = and a quoted encoded value', ->
      many_characters = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~Ā"
      authorization = example_request({consumer_key: many_characters}).authorization
      -- only alphas, numerics, and -._~ remain unencoded per 3.6
      -- hexes are uppercase 
      assert authorization.include?('consumer_key="%20%21%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%C4%80"')

    it 'generally looks like: OAuth key="quoted-value", anotherkey="anothervalue"', ->
      assert_equal('OAuth ' +
        'oauth_consumer_key="a%20consumer%20key", ' +
        'oauth_signature="a%2520consumer%2520secret%26", ' +
        'oauth_signature_method="PLAINTEXT", ' +
        'oauth_version="1.0"',
        example_request.authorization
      )

  describe 'signature', ->
    describe 'PLAINTEXT', ->
      it 'signs with the consumer and token secrets, encoded and &-joined', ->
        request = example_request({token: 'a token', token_secret: 'a token secret', signature_method: 'PLAINTEXT'})
        assert_equal('a%20consumer%20secret&a%20token%20secret', request.signed_protocol_params['oauth_signature'])

    describe 'HMAC-SHA1', ->
      it 'signs with a HMAC-SHA1 digest of the signature base', ->
        request = example_request(
          token: 'a token',
          token_secret: 'a token secret',
          signature_method: 'HMAC-SHA1',
          nonce: 'a nonce',
          timestamp: 1397726597,
          hash_body?: false
        )
        assert_equal('rVKcy4CgAih1kv4HAMGiNnjmUJk=', request.signed_protocol_params['oauth_signature'])

    describe 'RSA-SHA1', ->
      it 'signs with a RSA private key SHA1 signature', ->
        request = example_request(
          consumer_secret: rsa_private_key,
          token: 'a token',
          token_secret: 'a token secret',
          signature_method: 'RSA-SHA1',
          nonce: 'a nonce',
          timestamp: 1397726597,
          hash_body?: false
        )
        assert_equal(
          "s3/TkrCJw54tOpsKUHkoQ9PeH1r4wB2fNb70XC2G1ef7Wb/dwwNUOhtjtpGMSDhmYQHzEPt0dAJ+PgeNs1O5NZJQB5JqdsmrhLS3ZdHx2iucxYvZSuDNi0GxaEepz5VS9rg+y5Gmep60BpAKhX0KGnkMY9HIhomTPSrYidAfDOE=",
          request.signed_protocol_params['oauth_signature']
        )

      it 'ignores the token secret', ->
        request_attrs = {
          consumer_secret: rsa_private_key,
          token: 'a token',
          signature_method: 'RSA-SHA1',
          nonce: 'a nonce',
          timestamp: 1397726597,
        }
        request1 = example_request(request_attrs.merge({token_secret: 'a token secret'}))
        request2 = example_request(request_attrs.merge({token_secret: 'an entirely different token secret'}))
        assert_equal(request1.signature, request2.signature)
        assert_equal(request1.authorization, request2.authorization)

      describe 'with an invalid key', ->
        it 'errors', ->
          assert_raises(OpenSSL::PKey::RSAError) { example_request({signature_method: 'RSA-SHA1'}).signature }

  describe 'protocol_params', ->
    it 'includes given protocol params with an oauth_ prefix', ->
      OAuthenticator::SignableRequest::PROTOCOL_PARAM_KEYS.each do |param_key|
        assert_equal(example_request({param_key => 'a value'}).protocol_params["oauth_#{param_key}"], 'a value')
    it 'does not include a calculated signature', ->
      assert !example_request.protocol_params.key?('oauth_signature')
    it 'does include the signature of a given authorization', ->
      assert_equal('a signature', example_signed_request({oauth_signature: 'a signature'}).protocol_params['oauth_signature'])
    it 'does include unknown parameters of a given authorization', ->
      assert_equal('bar', example_signed_request({foo: 'bar'}).protocol_params['foo'])

  describe 'signed_protocol_params', ->
    it 'includes a signature', ->
      assert_equal 'a%20consumer%20secret&', example_request.signed_protocol_params['oauth_signature']

    it 'has a different signature than the given authorization if the given authorization is wrong', ->
      request = example_signed_request({
          oauth_consumer_key: 'a consumer key',
          oauth_signature: 'wrong%20secret&',
          oauth_signature_method: 'PLAINTEXT',
        },
        {consumer_secret: 'a consumer secret'}
      )
      refute_equal(
        request.protocol_params['oauth_signature'],
        request.signed_protocol_params['oauth_signature']
      )

  describe 'uri, per section 3.4.1.2', ->
    it 'lowercases scheme and host', ->
      [
        'http://example.com/FooBar',
        'Http://Example.com/FooBar',
        'HTTP://EXAMPLE.cOM/FooBar',
      ].each do |uri|
        assert_equal('http://example.com/FooBar', example_request({uri: uri}).send(:base_string_uri))

    it 'normalizes port', ->
      assert_equal('http://example.com/F', example_request({uri: 'http://example.com/F'}).send(:base_string_uri))
      assert_equal('http://example.com/F', example_request({uri: 'http://example.com:80/F'}).send(:base_string_uri))
      assert_equal('http://example.com:81/F', example_request({uri: 'http://example.com:81/F'}).send(:base_string_uri))
      assert_equal('https://example.com/F', example_request({uri: 'https://example.com/F'}).send(:base_string_uri))
      assert_equal('https://example.com/F', example_request({uri: 'https://example.com:443/F'}).send(:base_string_uri))
      assert_equal('https://example.com:444/F', example_request({uri: 'https://example.com:444/F'}).send(:base_string_uri))

    it 'excludes query and fragment', ->
      assert_equal('http://example.com/FooBar', example_request({uri: 'http://example.com/FooBar?foo=bar#foobar'}).send(:base_string_uri))

  it 'accepts string or symbol request methods', ->
    {GET: [:get, :Get, :GET, 'GeT', 'get'], OPTIONS: [:options, 'Options']}.each do |norm, variants|
      variants.each do |request_method|
        assert_equal(norm, example_request({request_method: request_method}).send(:normalized_request_method))

  describe 'body', ->
    it 'takes a string', ->
      assert_equal('abody', example_request({body: 'abody'}).send(:read_body))
    it 'takes an IO', ->
      assert_equal('abody', example_request({body: StringIO.new('abody')}).send(:read_body))
    it 'takes nil', ->
      assert_equal('', example_request({body: nil}).send(:read_body))
    it 'rejects something else', ->
      assert_raises(TypeError) { example_request({body: Object.new}).send(:read_body) }
    it 'calculates their authorization the same', ->
      request_io_body = example_request({body: StringIO.new('abody')})
      request_str_body = example_request({body: 'abody'})
      assert_equal(request_io_body.authorization, request_str_body.authorization)

  describe 'signature_base', ->
    it 'includes unrecognized authorization params when calculating signature base', ->
      authorization = 'OAuth realm="Example",
        oauth_foo="bar",
        oauth_consumer_key="9djdj82h48djs9d2",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131201",
        oauth_nonce="7d8f3e4a"
      '
      assert(example_signed_request(OAuthenticator.parse_authorization(authorization)).send(:signature_base).include?("oauth_foo%3Dbar"))

    it 'does include body in a formencoded request', ->
      assert(example_request({media_type: 'application/x-www-form-urlencoded', body: 'foo=bar'}).send(:signature_base).include?('foo'))

    it 'does include body in a formencoded request with alternate capitalization', ->
      assert(example_request({media_type: 'APPLICATION/X-WWW-FORM-URLENCODED', body: 'foo=bar'}).send(:signature_base).include?('foo'))

    it 'does not include body in a non-formencoded request', ->
      assert(!example_request({media_type: 'text/plain', body: 'foo=bar'}).send(:signature_base).include?('foo'))

  describe 'normalized request params', ->
    describe 'normalized request params string', ->
      -- this is effectively tested by #authorization so we won't here 
    describe 'protocol params', ->
      it 'does not include realm with a new request', ->
        request = example_request({realm: 'everywhere'})
        assert(!request.send(:normalized_request_params).any? { |k,v| k.downcase == 'realm' })
      it 'does not include realm with a previously-signed request', ->
        request = example_signed_request({realm: 'somewhere'})
        assert(!request.send(:normalized_request_params).any? { |k,v| k.downcase == 'realm' })
      it 'does not include signature', ->
        request = example_signed_request({oauth_signature: 'totallylegit', foo: 'bar'})
        assert(!request.send(:normalized_request_params).any? { |k,v| k.downcase == 'oauth_signature' })
      it 'does include all other given params', ->
        request = example_signed_request({
          realm: 'somewhere',
          foo: 'bar',
          oauth_signature: 'totallylegit',
          oauth_timestamp: '137131201'
        })
        [['foo', 'bar'], ['oauth_timestamp', '137131201']].each do |pair|
          assert(request.send(:normalized_request_params).include?(pair))
    describe 'query params', ->
      it 'goes into normalized request params', ->
        request = example_request({uri: 'http://example.com/?a=b&c=d&e=&f'})
        [['a', 'b'], ['c', 'd'], ['e', ''], ['f', nil]].each do |pair|
          assert(request.send(:normalized_request_params).include?(pair))
      it 'is empty with no query', ->
        request = example_request({uri: 'http://example.com/'})
        assert_equal([], request.send(:query_params))
      it 'decodes a + sign', ->
        request = example_request({uri: 'http://example.com/?a+key=a+value'})
        assert_equal([['a key', 'a value']], request.send(:query_params))
      it 'decodes %-encoded', ->
        request = example_request({uri: 'http://example.com/?a%20key=a%20value'})
        assert_equal([['a key', 'a value']], request.send(:query_params))
      it 'includes form encoded keys with an = sign and no value', ->
        request = example_request({uri: 'http://example.com/?a='})
        assert_equal([['a', '']], request.send(:query_params))
      it 'includes form encoded keys with no = sign and no value', ->
        request = example_request({uri: 'http://example.com/?a'})
        assert_equal([['a', nil]], request.send(:query_params))
    describe 'entity params', ->
      it 'goes into normalized request params', ->
        request = example_request({body: 'a=b&c=d&e=&f', media_type: 'application/x-www-form-urlencoded'})
        [['a', 'b'], ['c', 'd'], ['e', ''], ['f', nil]].each do |pair|
          assert(request.send(:normalized_request_params).include?(pair))
      it 'includes all form encoded params', ->
        request = example_request({body: 'a=b&c=d', media_type: 'application/x-www-form-urlencoded'})
        assert_equal([['a', 'b'], ['c', 'd']], request.send(:entity_params))
      it 'includes no non-form encoded params', ->
        request = example_request({body: 'a=b&c=d', media_type: 'text/plain'})
        assert_equal([], request.send(:entity_params))
      it 'does not parse nested params', ->
        request = example_request({body: 'a[b]=c', media_type: 'application/x-www-form-urlencoded'})
        assert_equal([['a[b]', 'c']], request.send(:entity_params))
      it 'decodes a + sign', ->
        request = example_request({body: 'a+key=a+value', media_type: 'application/x-www-form-urlencoded'})
        assert_equal([['a key', 'a value']], request.send(:entity_params))
      it 'decodes %-encoded keys and values', ->
        request = example_request({body: 'a%20key=a%20value', media_type: 'application/x-www-form-urlencoded'})
        assert_equal([['a key', 'a value']], request.send(:entity_params))
      it 'includes form encoded keys with an = sign and no value', ->
        request = example_request({body: 'a=', media_type: 'application/x-www-form-urlencoded'})
        assert_equal([['a', '']], request.send(:entity_params))
      it 'includes form encoded keys with no = sign and no value', ->
        request = example_request({body: 'a', media_type: 'application/x-www-form-urlencoded'})
        assert_equal([['a', nil]], request.send(:entity_params))

  describe 'body hash', ->
    describe 'default inclusion', ->
      it 'includes by default with non-form-encoded and HMAC-SHA1', ->
        request = example_request({media_type: 'text/plain', body: 'foo=bar', signature_method: 'HMAC-SHA1'})
        assert_equal('L7j0ARXdHmlcviPU+Xzlsftpfu4=', request.protocol_params['oauth_body_hash'])
      it 'includes by default with non-form-encoded and RSA-SHA1', ->
        request = example_request({media_type: 'text/plain', body: 'foo=bar', signature_method: 'RSA-SHA1', consumer_secret: rsa_private_key})
        assert_equal('L7j0ARXdHmlcviPU+Xzlsftpfu4=', request.protocol_params['oauth_body_hash'])
      it 'does not include by default with non-form-encoded and PLAINTEXT', ->
        request = example_request({media_type: 'text/plain', body: 'foo=bar', signature_method: 'PLAINTEXT'})
        assert(!request.protocol_params.key?('oauth_body_hash'))
      it 'does not include by default with form-encoded and HMAC-SHA1', ->
        request = example_request({media_type: 'application/x-www-form-urlencoded', body: 'foo=bar', signature_method: 'HMAC-SHA1'})
        assert(!request.protocol_params.key?('oauth_body_hash'))
      it 'does not include by default with form-encoded and RSA-SHA1', ->
        request = example_request({media_type: 'application/x-www-form-urlencoded', body: 'foo=bar', signature_method: 'RSA-SHA1', consumer_secret: rsa_private_key})
        assert(!request.protocol_params.key?('oauth_body_hash'))
      it 'does not include by default with form-encoded and PLAINTEXT', ->
        request = example_request({media_type: 'application/x-www-form-urlencoded', body: 'foo=bar', signature_method: 'PLAINTEXT'})
        assert(!request.protocol_params.key?('oauth_body_hash'))
    it 'respects the :hash_body? option', ->
      attributes = {media_type: 'text/plain', body: 'foo=bar', signature_method: 'HMAC-SHA1'}
      -- ensure these would generate the hash by default, without :hash_body?
      assert_equal('L7j0ARXdHmlcviPU+Xzlsftpfu4=', example_request(attributes).protocol_params['oauth_body_hash'])
      assert(!example_request(attributes.merge({'hash_body?': false})).protocol_params.key?('oauth_body_hash'))
      assert_equal('L7j0ARXdHmlcviPU+Xzlsftpfu4=', example_request(attributes.merge({'hash_body?': true})).protocol_params['oauth_body_hash'])
    it 'does not generate a body hash when given a authorization', ->
      assert(!example_signed_request({}).protocol_params.key?('oauth_body_hash'))

    describe '#body_hash', ->
      it 'is the same as goes in protocol params when generated', ->
        request = example_request({media_type: 'text/plain', body: 'foo=bar', signature_method: 'HMAC-SHA1'})
        assert_equal(request.protocol_params['oauth_body_hash'], request.body_hash)
      it 'matches the given protocol params for a valid request', ->
        request = example_signed_request(
          {oauth_body_hash: 'Lve95gjOVATpfV8EL5X4nxwjKHE=', oauth_signature_method: 'HMAC-SHA1'},
          {body: 'Hello World!', media_type: 'text/plain'}
        )
        assert_equal(request.protocol_params['oauth_body_hash'], request.body_hash)
      it 'is different than the given protocol params for an invalid request', ->
        request = example_signed_request(
          {oauth_body_hash: 'helloooooo?=', oauth_signature_method: 'HMAC-SHA1'},
          {body: 'Hello World!', media_type: 'text/plain'}
        )
        refute_equal(request.protocol_params['oauth_body_hash'], request.body_hash)
      it 'returns nil for an unsupported signature method', ->
        assert_equal(nil, example_request({signature_method: 'PLAINTEXT'}).body_hash)

    describe 'example appendix A1', ->
      let :request do
        OAuthenticator::SignableRequest.new({
          request_method: 'PUT',
          uri: 'http://www.example.com/resource',
          media_type: 'text/plain',
          body: 'Hello World!',
          signature_method: 'HMAC-SHA1',
          token: "token",
          consumer_key: "consumer",
          timestamp: "1236874236",
          nonce: "10369470270925",
        })
      it 'has the same oauth body hash', ->
        assert_equal('Lve95gjOVATpfV8EL5X4nxwjKHE=', request.signed_protocol_params['oauth_body_hash'])
      it 'has the same signature base', ->
        assert_equal(
          'PUT&http%3A%2F%2Fwww.example.com%2Fresource&oauth_body_hash%3D' +
          'Lve95gjOVATpfV8EL5X4nxwjKHE%253D%26oauth_consumer_key%3Dconsum' +
          'er%26oauth_nonce%3D10369470270925%26oauth_signature_method%3DH' +
          'MAC-SHA1%26oauth_timestamp%3D1236874236%26oauth_token%3Dtoken%' +
          '26oauth_version%3D1.0',
          request.send(:signature_base)
        )
    describe 'example appendix A2', ->
      let :request do
        OAuthenticator::SignableRequest.new({
          request_method: 'GET',
          uri: 'http://www.example.com/resource',
          media_type: nil,
          body: nil,
          signature_method: 'HMAC-SHA1',
          token: "token",
          consumer_key: "consumer",
          timestamp: "1238395022",
          nonce: "8628868109991",
        })
      it 'has the same oauth body hash', ->
        assert_equal('2jmj7l5rSw0yVb/vlWAYkK/YBwk=', request.signed_protocol_params['oauth_body_hash'])
      it 'has the same signature base', ->
        assert_equal(
          'GET&http%3A%2F%2Fwww.example.com%2Fresource&oauth_body_hash%3D2jmj7' +
          'l5rSw0yVb%252FvlWAYkK%252FYBwk%253D%26oauth_consumer_key%3Dconsumer' +
          '%26oauth_nonce%3D8628868109991%26oauth_signature_method%3DHMAC-SHA1' +
          '%26oauth_timestamp%3D1238395022%26oauth_token%3Dtoken%26oauth_versi' +
          'on%3D1.0',
          request.send(:signature_base)
        )

  it 'reproduces a successful OAuth example GET (lifted from simple oauth)', ->
    request = OAuthenticator::SignableRequest.new(
      request_method: :get,
      uri: 'http://photos.example.net/photos',
      media_type: 'application/x-www-form-urlencoded',
      body: 'file=vacaction.jpg&size=original',
      consumer_key: 'dpf43f3p2l4k3l03',
      consumer_secret: rsa_private_key,
      nonce: '13917289812797014437',
      signature_method: 'RSA-SHA1',
      timestamp: '1196666512'
    )
    expected_protocol_params = {
      oauth_consumer_key: "dpf43f3p2l4k3l03",
      oauth_nonce: "13917289812797014437",
      oauth_signature: "jvTp/wX1TYtByB1m+Pbyo0lnCOLIsyGCH7wke8AUs3BpnwZJtAuEJkvQL2/9n4s5wUmUl4aCI4BwpraNx4RtEXMe5qg5T1LVTGliMRpKasKsW//e+RinhejgCuzoH26dyF8iY2ZZ/5D1ilgeijhV/vBka5twt399mXwaYdCwFYE=",
      oauth_signature_method: "RSA-SHA1",
      oauth_timestamp: "1196666512",
      oauth_version: "1.0",
    }

    assert_equal(expected_protocol_params, request.signed_protocol_params)

  it 'reproduces a successful OAuth example GET (lifted from simple oauth)', ->
    request = OAuthenticator::SignableRequest.new(
      request_method: :get,
      uri: 'http://host.net/resource?name=value',
      media_type: 'application/x-www-form-urlencoded',
      body: 'name=value',
      consumer_key: 'abcd',
      consumer_secret: 'efgh',
      token: 'ijkl',
      token_secret: 'mnop',
      nonce: 'oLKtec51GQy',
      signature_method: 'PLAINTEXT',
      timestamp: '1286977095'
    )
    expected_protocol_params = {
      oauth_consumer_key: "abcd",
      oauth_nonce: "oLKtec51GQy",
      oauth_signature: "efgh&mnop",
      oauth_signature_method: "PLAINTEXT",
      oauth_timestamp: "1286977095",
      oauth_token: "ijkl",
      oauth_version: "1.0"
    }

    assert_equal(expected_protocol_params, request.signed_protocol_params)
