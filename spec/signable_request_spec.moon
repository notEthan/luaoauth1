luaoauth1 = require('luaoauth1/luaoauth1')
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
-----END PRIVATE KEY-----"

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
      spec_authorization = luaoauth1.parse_authorization('OAuth realm="Example",
        oauth_consumer_key="9djdj82h48djs9d2",
        oauth_token="kkk9d7dh3k39sjv7",
        oauth_signature_method="HMAC-SHA1",
        oauth_timestamp="137131201",
        oauth_nonce="7d8f3e4a",
        oauth_signature="r6%2FTJjbCOr97%2F%2BUU0NsvSne7s5g%3D"
      ')
      assert.same(spec_authorization, spec_request()\signed_protocol_params())

  describe '#authorization', ->
    it 'has the parameter name followed by an = and a quoted encoded value', ->
      many_characters = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~Ā"
      authorization = example_request({consumer_key: many_characters})\authorization()
      -- only alphas, numerics, and -._~ remain unencoded per 3.6
      -- hexes are uppercase 
      encoded = 'consumer_key="%20%21%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~%C4%80"'
      assert.truthy authorization\find(encoded, 1, true)

    it 'generally looks like: OAuth key="quoted-value", anotherkey="anothervalue"', ->
      authorization = 'OAuth ' ..
        'oauth_consumer_key="a%20consumer%20key", ' ..
        'oauth_signature="a%2520consumer%2520secret%26", ' ..
        'oauth_signature_method="PLAINTEXT", ' ..
        'oauth_version="1.0"'
      -- TODO assert.same(authorization, example_request()\authorization())

  describe 'signature', ->
    describe 'PLAINTEXT', ->
      it 'signs with the consumer and token secrets, encoded and &-joined', ->
        request = example_request({token: 'a token', token_secret: 'a token secret', signature_method: 'PLAINTEXT'})
        assert.same('a%20consumer%20secret&a%20token%20secret', request\signed_protocol_params()['oauth_signature'])

    describe 'HMAC-SHA1', ->
      it 'signs with a HMAC-SHA1 digest of the signature base', ->
        request = example_request({
          token: 'a token',
          token_secret: 'a token secret',
          signature_method: 'HMAC-SHA1',
          nonce: 'a nonce',
          timestamp: 1397726597,
          hash_body: false
        })
        assert.same('rVKcy4CgAih1kv4HAMGiNnjmUJk=', request\signed_protocol_params()['oauth_signature'])

    describe 'RSA-SHA1', ->
      it 'signs with a RSA private key SHA1 signature', ->
        request = example_request({
          consumer_secret: rsa_private_key(),
          token: 'a token',
          token_secret: 'a token secret',
          signature_method: 'RSA-SHA1',
          nonce: 'a nonce',
          timestamp: 1397726597,
          hash_body: false
        })
        signature = "s3/TkrCJw54tOpsKUHkoQ9PeH1r4wB2fNb70XC2G1ef7Wb/dwwNUOhtjtpGMSDhmYQHzEPt0dAJ+PgeNs1O5NZJQB5JqdsmrhLS3ZdHx2iucxYvZSuDNi0GxaEepz5VS9rg+y5Gmep60BpAKhX0KGnkMY9HIhomTPSrYidAfDOE="
        assert.same(signature, request\signed_protocol_params()['oauth_signature'])

      it 'ignores the token secret', ->
        request_attrs = {
          consumer_secret: rsa_private_key(),
          token: 'a token',
          signature_method: 'RSA-SHA1',
          nonce: 'a nonce',
          timestamp: 1397726597,
        }
        request1 = example_request(merge(request_attrs, {token_secret: 'a token secret'}))
        request2 = example_request(merge(request_attrs, {token_secret: 'an entirely different token secret'}))
        assert.same(request1\signature(), request2\signature())
        assert.same(request1\authorization(), request2\authorization())

      describe 'with an invalid key', ->
        it 'errors', ->
          assert.has_error, -> example_request({signature_method: 'RSA-SHA1'})\signature()

