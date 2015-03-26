class SignedRequest
  PROTOCOL_PARAM_KEYS: {k, true for k in {'consumer_key', 'token', 'signature_method', 'timestamp', 'nonce', 'version'}}
  RECOGNIZED_KEYS: {k, true for k in {'authorization', 'consumer_secret', 'token_secret', 'realm', 'hash_body'}}

  new: (attributes) =>
    unless type(attributes) == 'table'
      error("attributes must be a table")

    @attributes = attributes

    -- validation - presence
    required = {'request_method', 'uri', 'media_type', 'body'}
    unless @attributes['authorization']
      required[#required] = k for k in *{'signature_method', 'consumer_key'}
    missing = [k for k in *required when not @attributes[k]]
    error("missing required attributes: #{missing}") if #missing > 0
    extra = [k for k, _ in ipairs(@attributes) when not PROTOCOL_PARAM_KEYS[k] or RECOGNIZED_KEYS[k]]
    error("received unrecognized attributes: #{extra.inspect}") if #extra > 0

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
        defaults['timestamp'] = 'now' -- TODO
      @attributes['authorization'] = {"oauth_#{key}", @attributes[key] or defaults[key] for key, _ in PROTOCOL_PARAM_KEYS}

      @attributes['authorization']['realm'] = @attributes['realm'] if @attributes['realm'] != nil

      hash_body()

  -- returns the Authorization header generated for this request.
  --
  -- @return [String] Authorization header
  authorization: =>
    "OAuth #{normalized_protocol_params_string()}"

  -- the oauth_signature calculated for this request.
  --
  -- @return [String] oauth signature
  signature: =>
    rbmethod = SIGNATURE_METHODS[signature_method] ||
      raise(ArgumentError, "invalid signature method: #{signature_method}")
    rbmethod.bind(self).call

  -- the oauth_body_hash calculated for this request, if applicable, per the OAuth Request Body Hash 
  -- specification.
  --
  -- @return [String, nil] oauth body hash
  body_hash: =>
    BODY_HASH_METHODS[signature_method] ? BODY_HASH_METHODS[signature_method].bind(self).call : nil

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
    @attributes['authorization'].dup

  -- protocol params for this request as described in section 3.4.1.3, including our calculated 
  -- oauth_signature.
  --
  -- @return [Hash<String, String>] signed protocol params
  signed_protocol_params: =>
    protocol_params.merge('oauth_signature' => signature)

  -- is the media type application/x-www-form-urlencoded
  --
  -- @return [Boolean]
  is_form_encoded: =>
    media_type = @attributes['media_type']
    -- media tye is case insensitive per http://www.w3.org/Protocols/rfc2616/rfc2616-sec3.html#sec3.7
    media_type = media_type.downcase if media_type.is_a?(String)
    media_type == "application/x-www-form-urlencoded"

  private

  -- signature base string for signing. section 3.4.1
  --
  -- @return [String]
  signature_base: =>
    parts = [normalized_request_method, base_string_uri, normalized_request_params_string]
    parts.map { |v| OAuthenticator.escape(v) }.join('&')

  -- section 3.4.1.2
  --
  -- @return [String]
  base_string_uri: =>
    Addressable::URI.parse(@attributes['uri'].to_s).tap do |uri|
      uri.scheme = uri.scheme.downcase if uri.scheme
      uri.host = uri.host.downcase if uri.host
      uri.normalize!
      uri.fragment = nil
      uri.query = nil
    end.to_s

  -- section 3.4.1.1
  --
  -- @return [String]
  normalized_request_method: =>
    @attributes['request_method'].to_s.upcase

  -- section 3.4.1.3.2
  --
  -- @return [String]
  normalized_request_params_string: =>
    normalized_request_params.map { |kv| kv.map { |v| OAuthenticator.escape(v) } }.sort.map { |p| p.join('=') }.join('&')

  -- section 3.4.1.3
  --
  -- @return [Array<Array<String> (size 2)>]
  normalized_request_params: =>
    query_params + protocol_params.reject { |k,v| %w(realm oauth_signature).include?(k) }.to_a + entity_params

  -- section 3.4.1.3.1
  --
  -- parsed query params, extracted from the request URI. since keys may appear multiple times, represented 
  -- as an array of two-element arrays and not a hash
  --
  -- @return [Array<Array<String, nil> (size 2)>]
  query_params: =>
    parse_form_encoded(URI.parse(@attributes['uri'].to_s).query || '')

  -- section 3.4.1.3.1
  --
  -- parsed entity params from the body, when the request is form encoded. since keys may appear multiple 
  -- times, represented as an array of two-element arrays and not a hash
  --
  -- @return [Array<Array<String, nil> (size 2)>]
  entity_params: =>
    if form_encoded?
      parse_form_encoded(read_body)
    else
      []

  -- like CGI.parse but it keeps keys without any value. doesn't keep blank keys though.
  --
  -- @return [Array<Array<String, nil> (size 2)>]
  def parse_form_encoded(data)
    data.split(/[&;]/).map do |pair|
      key, value = pair.split('=', 2).map { |v| CGI::unescape(v) }
      [key, value] unless [nil, ''].include?(key)
    end.compact

  -- string of protocol params including signature, sorted 
  --
  -- @return [String]
  normalized_protocol_params_string: =>
    signed_protocol_params.sort.map { |(k,v)| %Q(#{OAuthenticator.escape(k)}="#{OAuthenticator.escape(v)}") }.join(', ')

  -- reads the request body, be it String or IO 
  --
  -- @return [String] request body
  read_body: =>
    body = @attributes['body']
    if body.nil?
      ''
    elsif body.is_a?(String)
      body
    elsif body.respond_to?(:read) && body.respond_to?(:rewind)
      body.rewind
      body.read.tap do
        body.rewind
    else
      raise TypeError, "Body must be a String or something IO-like (responding to #read and #rewind). " +
        "got body = #{body.inspect}"

  -- set the oauth_body_hash to the hash of the request body 
  --
  -- @return [Void]
  hash_body: =>
    if hash_body?
      @attributes['authorization']['oauth_body_hash'] = body_hash

  -- whether we will hash the body, per oauth request body hash section 4.1, as well as whether the caller 
  -- said to 
  --
  -- @return [Boolean]
  will_hash_body: =>
    BODY_HASH_METHODS[signature_method] && !form_encoded? &&
      (@attributes.key?('hash_body?') ? @attributes['hash_body?'] : true)

  -- signature method 
  --
  -- @return [String]
  signature_method: =>
    @attributes['authorization']['oauth_signature_method']

  -- signature, with method RSA-SHA1. section 3.4.3 
  --
  -- @return [String]
  rsa_sha1_signature: =>
    private_key = OpenSSL::PKey::RSA.new(@attributes['consumer_secret'])
    Base64.encode64(private_key.sign(OpenSSL::Digest::SHA1.new, signature_base)).gsub(/\n/, '')

  -- signature, with method HMAC-SHA1. section 3.4.2
  --
  -- @return [String]
  hmac_sha1_signature: =>
    -- hmac secret is same as plaintext signature 
    secret = plaintext_signature
    Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret, signature_base)).gsub(/\n/, '')

  -- signature, with method plaintext. section 3.4.4
  --
  -- @return [String]
  plaintext_signature: =>
    @attributes.values_at('consumer_secret', 'token_secret').map { |v| OAuthenticator.escape(v) }.join('&')

  -- body hash, with a signature method which uses SHA1. oauth request body hash section 3.2
  --
  -- @return [String]
  sha1_body_hash: =>
    Base64.encode64(OpenSSL::Digest::SHA1.digest(read_body)).gsub(/\n/, '')
