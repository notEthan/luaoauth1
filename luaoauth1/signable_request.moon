-- a request which may be signed with OAuth, generally in order to apply the signature to an outgoing request 
-- in the Authorization header.
--
-- primarily this is to be used like:
--
--     oauthenticator_signable_request = OAuthenticator::SignableRequest.new(
--       :request_method => my_request_method,
--       :uri => my_request_uri,
--       :media_type => my_request_media_type,
--       :body => my_request_body,
--       :signature_method => my_oauth_signature_method,
--       :consumer_key => my_oauth_consumer_key,
--       :consumer_secret => my_oauth_consumer_secret,
--       :token => my_oauth_token,
--       :token_secret => my_oauth_token_secret,
--       :realm => my_authorization_realm
--     )
--     my_http_request.headers['Authorization'] = oauthenticator_signable_request.authorization
class SignedRequest
  -- keys of OAuth protocol parameters which form the Authorization header (with an oauth_ prefix). 
  -- signature is considered separately.
  PROTOCOL_PARAM_KEYS: {k, true for k in *{'consumer_key', 'token', 'signature_method', 'timestamp', 'nonce', 'version'}}

  -- other recognized keys that can be given as arguments to initialize an instance
  RECOGNIZED_KEYS: {k, true for k in *{'authorization', 'consumer_secret', 'token_secret', 'realm', 'hash_body'}}

  -- map of oauth signature methods to their signature instance methods on this class 
  SIGNATURE_METHODS: {
    'RSA-SHA1': 'rsa_sha1_signature',
    'HMAC-SHA1': 'hmac_sha1_signature',
    'PLAINTEXT': 'plaintext_signature',
  }

  -- map of oauth signature methods to their body hash instance methods on this class. oauth request body 
  -- hash section 3.1
  BODY_HASH_METHODS: {
    'RSA-SHA1': 'sha1_body_hash',
    'HMAC-SHA1': 'sha1_body_hash',
  }

  new: (attributes) =>
    unless type(attributes) == 'table'
      error("attributes must be a table")

    @attributes = {k, v for k, v in pairs(attributes)}

    -- validation - presence
    required = {'request_method', 'uri', 'media_type', 'body'}
    unless @attributes['authorization']
      required[#required] = k for k in *{'signature_method', 'consumer_key'}
    missing = [k for k in *required when not @attributes[k]]
    error("missing required attributes: #{table.concat(missing, ', ')}") if #missing > 0
    extra = [k for k, _ in pairs(@attributes) when not PROTOCOL_PARAM_KEYS[k] or RECOGNIZED_KEYS[k]]
    error("received unrecognized attributes: #{table.concat(extra, ', ')}") if #extra > 0

    if @attributes['authorization']
      -- this means we are signing an existing request to validate the received signature. don't use defaults.

      unless type(@attributes['authorization']) == 'table'
        error("authorization must be a table")

      -- if authorization is specified, protocol params should not be specified in the regular attributes 
      given_protocol_params = {k, v for k, v in ipairs(@attributes) when PROTOCOL_PARAM_KEYS[k] and v}
      if #given_protocol_params > 0
        error("an existing authorization was given, but protocol parameters were also " ..
          "given. protocol parameters should not be specified when verifying an existing authorization. " ..
          "given protocol parameters were: #{given_protocol_params.inspect}")
    else
      -- defaults
      defaults = {
        'version': '1.0',
      }
      if @attributes['signature_method'] != 'PLAINTEXT'
        defaults['nonce'] = 'TMP' -- TODO
        defaults['timestamp'] = tostring(os.time())
      @attributes['authorization'] = {"oauth_#{key}", @attributes[key] or defaults[key] for key, _ in PROTOCOL_PARAM_KEYS}

      @attributes['authorization']['realm'] = @attributes['realm'] if @attributes['realm'] != nil

      @hash_body()

  -- returns the Authorization header generated for this request.
  --
  -- @return [String] Authorization header
  authorization: =>
    "OAuth #{@normalized_protocol_params_string()}"

  -- the oauth_signature calculated for this request.
  --
  -- @return [String] oauth signature
  signature: =>
    sigmethod = SIGNATURE_METHODS[@signature_method()] or error("invalid signature method: #{@signature_method()}")
    sigmethod()

  -- the oauth_body_hash calculated for this request, if applicable, per the OAuth Request Body Hash 
  -- specification.
  --
  -- @return [String, nil] oauth body hash
  body_hash: =>
    hashmethod = BODY_HASH_METHODS[@signature_method()]
    hashmethod() if hashmethod

  -- protocol params for this request as described in section 3.4.1.3 
  --
  -- signature is not calculated for this - use #signed_protocol_params to get protocol params including a 
  -- signature. 
  --
  -- note that if this is a previously-signed request, the oauth_signature attribute returned is the 
  -- received value, NOT the value calculated by us.
  --
  -- @return [Hash<String, String>] protocol params
  protocol_params: =>
    {k, v for k, v in pairs(@attributes['authorization'])}

  -- protocol params for this request as described in section 3.4.1.3, including our calculated 
  -- oauth_signature.
  --
  -- @return [Hash<String, String>] signed protocol params
  signed_protocol_params: =>
    with @protocol_params()
      .oauth_signature = @signature()

  -- is the media type application/x-www-form-urlencoded
  --
  -- @return [Boolean]
  is_form_encoded: =>
    media_type = @attributes['media_type']
    -- media tye is case insensitive per http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7
    media_type = media_type\lower() if type(media_type) == 'string'
    media_type == "application/x-www-form-urlencoded"

  -- private

  -- signature base string for signing. section 3.4.1
  --
  -- @return [String]
  signature_base: =>
    parts = {@normalized_request_method(), @base_string_uri(), @normalized_request_params_string()}
    parts = [OAuthenticator.escape(part) for part in *parts]
    table.concat(parts, '&')

  -- section 3.4.1.2
  --
  -- @return [String]
  base_string_uri: =>
    @attributes['uri'] -- TODO
    -- Addressable::URI.parse(@attributes['uri'].to_s).tap do |uri|
    --   uri.scheme = uri.scheme.downcase if uri.scheme
    --   uri.host = uri.host.downcase if uri.host
    --   uri.normalize!
    --   uri.fragment = nil
    --   uri.query = nil
    -- end.to_s

  -- section 3.4.1.1
  --
  -- @return [String]
  normalized_request_method: =>
    @attributes['request_method']\upper()

  -- section 3.4.1.3.2
  --
  -- @return [String]
  normalized_request_params_string: =>
    -- normalized_request_params.map { |kv| kv.map { |v| OAuthenticator.escape(v) } }.sort.map { |p| p.join('=') }.join('&')
    escaped = [ [OAuthenticator.escape(x) for x in param] for param in *@normalized_request_params()]
    sorted = @sort_params(escaped)
    table.concat([table.concat(e, '=') for e in sorted], '&')

  -- section 3.4.1.3
  --
  -- @return [Array<Array<String> (size 2)>]
  normalized_request_params: =>
    normalized_request_params = {}
    normalized_request_params[#normalized_request_params] = e for e in *query_params
    normalized_request_params[#normalized_request_params] = e for e in *protocol_params when not (e[1] == 'realm' or e[1] == 'oauth_signature')
    normalized_request_params[#normalized_request_params] = e for e in *entity_params
    normalized_request_params

  -- section 3.4.1.3.1
  --
  -- parsed query params, extracted from the request URI. since keys may appear multiple times, represented 
  -- as an array of two-element arrays and not a hash
  --
  -- @return [Array<Array<String, nil> (size 2)>]
  query_params: =>
    --parse_form_encoded(URI.parse(@attributes['uri'].to_s).query || '')
    query = '' -- TODO
    @parse_form_encoded(query)

  -- section 3.4.1.3.1
  --
  -- parsed entity params from the body, when the request is form encoded. since keys may appear multiple 
  -- times, represented as an array of two-element arrays and not a hash
  --
  -- @return [Array<Array<String, nil> (size 2)>]
  entity_params: =>
    if @is_form_encoded()
      @parse_form_encoded(@body)
    else
      {}

  -- like CGI.parse but it keeps keys without any value. doesn't keep blank keys though.
  --
  -- @return [Array<Array<String, nil> (size 2)>]
  parse_form_encoded: (data) =>
    --data.split(/[&;]/).map do |pair|
    --  key, value = pair.split('=', 2).map { |v| CGI::unescape(v) }
    --  [key, value] unless [nil, ''].include?(key)
    --end.compact
    {} -- TODO

  -- string of protocol params including signature, sorted 
  --
  -- @return [String]
  normalized_protocol_params_string: =>
    -- signed_protocol_params.sort.map { |(k,v)| %Q(#{OAuthenticator.escape(k)}="#{OAuthenticator.escape(v)}") }.join(', ')
    sorted_params = @sort_params(@signed_protocol_params())
    escaped_params = [ [[#{OAuthenticator.escape(k)}="#{OAuthenticator.escape(v)}"]] for k, v in pairs(sorted_params)]
    table.concat(escaped_params, ', ')

  -- reads the request body, be it String or IO 
  --
  -- @return [String] request body
  body: =>
    @attributes['body'] or ''

  -- set the oauth_body_hash to the hash of the request body 
  --
  -- @return [Void]
  hash_body: =>
    if @will_hash_body()
      @attributes['authorization']['oauth_body_hash'] = @body_hash()

  -- whether we will hash the body, per oauth request body hash section 4.1, as well as whether the caller 
  -- said to 
  --
  -- @return [Boolean]
  will_hash_body: =>
    BODY_HASH_METHODS[signature_method] and @is_form_encoded() and @attributes['hash_body?'] != false

  -- signature method 
  --
  -- @return [String]
  signature_method: =>
    @attributes['authorization']['oauth_signature_method']

  -- signature, with method RSA-SHA1. section 3.4.3 
  --
  -- @return [String]
  rsa_sha1_signature: =>
    base64encodenonl(crypto.sign('sha1', @signature_base(), @attributes['consumer_secret']))

  -- signature, with method HMAC-SHA1. section 3.4.2
  --
  -- @return [String]
  hmac_sha1_signature: =>
    -- hmac secret is same as plaintext signature 
    secret = @plaintext_signature()
    --Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret, signature_base)).gsub(/\n/, '')
    base64encodenonl(crypto.hmac.digest('sha1', @signature_base(), secret, true))

  -- signature, with method plaintext. section 3.4.4
  --
  -- @return [String]
  plaintext_signature: =>
    table.concat([OAuthenticator.escape(@attributes[k]) for k in *{'consumer_secret', 'token_secret'} when @attributes[k]])

  -- body hash, with a signature method which uses SHA1. oauth request body hash section 3.2
  --
  -- @return [String]
  sha1_body_hash: =>
    base64encodenonl(crypto.digest('sha1', @body(), true))

  sort_params: (params) =>
    return table.sort(params, (a, b) ->
      {ak, av} = a
      {bk, bv} = b
      if ak == bk then av < bv else ak < bk
    )

SignedRequest
