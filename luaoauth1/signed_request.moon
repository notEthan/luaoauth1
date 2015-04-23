luaoauth1 = require('luaoauth1')
SignableRequest = require('luaoauth1.signable_request')

-- this class represents an OAuth signed request. its primary user-facing method is {#errors}, which returns 
-- nil if the request is valid and authentic, or a helpful object of error messages describing what was 
-- invalid if not. 
--
-- this class is not useful on its own, as various methods must be implemented on a module to be included 
-- before the implementation is complete enough to use. see the README and the documentation for the module 
-- {OAuthenticator::ConfigMethods} for details. to pass such a module to 
-- {OAuthenticator::SignedRequest}, use {.including_config}, like 
-- `OAuthenticator::SignedRequest.including_config(config_module)`.
class SignedRequest
  -- attributes of a SignedRequest
  ATTRIBUTE_KEYS: {k, true for k in *{'request_method', 'uri', 'body', 'media_type', 'authorization'}}

  -- oauth attributes parsed from the request authorization
  OAUTH_ATTRIBUTE_KEYS: do
    keys = {k, v for k, v in pairs(SignableRequest.PROTOCOL_PARAM_KEYS)}
    keys[key] = true for key in *{'signature', 'body_hash'}
    keys

  -- readers for oauth header parameters 
  --OAUTH_ATTRIBUTE_KEYS.each { |key| define_method(key) { oauth_header_params["oauth_#{key}"] } }

  -- question methods to indicate whether oauth header parameters were included with a non-blank value in 
  -- the Authorization header
  --OAUTH_ATTRIBUTE_KEYS.each do |key|
  --  define_method("#{key}?") do
  --    value = oauth_header_params["oauth_#{key}"]
  --    value.is_a?(String) ? !value.empty? : !!value

  -- initialize a {SignedRequest}. this should not be called on OAuthenticator::SignedRequest directly, but 
  -- a subclass made with {.including_config} - see {SignedRequest}'s documentation.
  new: (attributes, config_methods) =>
    unless type(attributes) == 'table'
      error("attributes must be a table")
    unless type(config_methods) == 'table'
      error("config_methods must be a table")

    @attributes = {k, v for k, v in pairs(attributes)}
    extra = [k for k, _ in pairs(@attributes) when not SignedRequest.ATTRIBUTE_KEYS[k]]
    if #extra > 0
      error("received unrecognized attributes: #{table.concat(extra, ', ')}")

    @config_methods = config_methods

  -- inspects the request represented by this instance of SignedRequest. if the request is authentically 
  -- signed with OAuth, returns nil to indicate that there are no errors. if the request is inauthentic or 
  -- invalid for any reason, this returns a hash containing the reason(s) why the request is invalid.
  --
  -- The error object's structure is a hash with string keys indicating attributes with errors, and values 
  -- being arrays of strings indicating error messages on the attribute key. this structure takes after 
  -- structured rails / ActiveResource, and looks like:
  --
  --     {'attribute1': ['messageA', 'messageB'], 'attribute2': ['messageC']}
  --
  -- @return [nil, Hash<String, Array<String>>] either nil or a hash of errors
  errors: =>
    return @errors_table if @errors_table != nil
    errors_function = ->
      if @authorization() == nil
        return({Authorization: {"Authorization header is missing"}})
      elseif not @authorization()\find('%S')
        return({Authorization: {"Authorization header is blank"}})

      ok, parse_exception = pcall(-> @oauth_header_params())
      if not ok
        if type(parse_exception) == 'table' and parse_exception.errors
          return parse_exception.errors
        else
          error(parse_exception)

      errors = {}
      add_error = (key, message) ->
        errors[key] = {} if not errors[key]
        table.insert(errors[key], message)

      -- timestamp
      if not @has_timestamp()
        unless @signature_method() == 'PLAINTEXT'
          add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is missing")
      elseif not @timestamp()\find('^%s*%d+%s*$')
        add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is not an integer - got: #{@timestamp()}")
      else
        timestamp_i = tonumber(@timestamp())
        if timestamp_i < os.time() - @timestamp_valid_past()
          add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is too old: #{@timestamp()}")
        elseif timestamp_i > os.time() + @timestamp_valid_future()
          add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is too far in the future: #{@timestamp()}")

      -- oauth version
      if @has_version() and @version() != '1.0'
        add_error('Authorization oauth_version', "Authorization oauth_version must be 1.0; got: #{@version()}")

      -- she's filled with secrets
      secrets = {}

      -- consumer / client application
      if not @has_consumer_key()
        add_error('Authorization oauth_consumer_key', "Authorization oauth_consumer_key is missing")
      else
        secrets['consumer_secret'] = @consumer_secret()
        if not secrets['consumer_secret']
          add_error('Authorization oauth_consumer_key', 'Authorization oauth_consumer_key is invalid')

      -- token
      if @has_token()
        secrets['token_secret'] = @token_secret()
        if not secrets['token_secret']
          add_error('Authorization oauth_token', 'Authorization oauth_token is invalid')
        elseif not @token_belongs_to_consumer()
          add_error('Authorization oauth_token', 'Authorization oauth_token does not belong to the specified consumer')

      -- nonce
      if not @has_nonce()
        unless @signature_method() == 'PLAINTEXT'
          add_error('Authorization oauth_nonce', "Authorization oauth_nonce is missing")
      elseif @is_nonce_used()
        add_error('Authorization oauth_nonce', "Authorization oauth_nonce has already been used")

      -- signature method
      if not @has_signature_method()
        add_error('Authorization oauth_signature_method', "Authorization oauth_signature_method is missing")
      else
        allowed_signature_method = false
        allowed_signature_method = true for sm in *@allowed_signature_methods() when @signature_method()\lower() == sm\lower()
        unless allowed_signature_method
          add_error('Authorization oauth_signature_method', "Authorization oauth_signature_method must be one of " ..
            "#{table.concat(@allowed_signature_methods(), ', ')}; got: #{@signature_method()}")

      -- signature
      if not @has_signature()
        add_error('Authorization oauth_signature', "Authorization oauth_signature is missing")

      sr_attributes = {k, v for k, v in pairs(@attributes)}
      sr_attributes[k] = v for k, v in pairs(secrets)
      sr_attributes['authorization'] = @oauth_header_params()
      signable_request = SignableRequest(sr_attributes)

      -- body hash

      -- present?
      if @has_body_hash()
        -- allowed?
        if not signable_request\is_form_encoded()
          -- applicable?
          has_key = false
          has_key = true for k, _ in pairs(SignableRequest.BODY_HASH_METHODS) when k == @signature_method()
          if has_key--(SignableRequest.BODY_HASH_METHODS, @signature_method())
            -- correct?
            if @body_hash() == signable_request\body_hash()
              -- all good
              nil
            else
              add_error('Authorization oauth_body_hash', "Authorization oauth_body_hash is invalid")
          else
            -- received a body hash with plaintext. weird situation - we will ignore it; signature will not 
            -- be verified but it will be a part of the signature. 
            nil
        else
          add_error('Authorization oauth_body_hash', "Authorization oauth_body_hash must not be included with form-encoded requests")
      else
        -- allowed?
        if not signable_request\is_form_encoded()
          -- required?
          if @body_hash_required()
            add_error('Authorization oauth_body_hash', "Authorization oauth_body_hash is required (on non-form-encoded requests)")
          else
            -- okay - not supported by client, but allowed
            nil
        else
          -- all good
          nil

      return(errors) if next(errors) != nil

      -- proceed to check signature
      unless @signature() == signable_request\signature()
        return({'Authorization oauth_signature': {"Authorization oauth_signature is invalid"}})

      if @has_nonce()
        ok, exception = pcall(-> @use_nonce())
        if not ok
          if type(exception) == 'table' and exception.type == 'luaoauth1.NonceUsedError'
            return({'Authorization oauth_nonce': {'Authorization oauth_nonce has already been used'}})
          else
            error(exception)

      false
    @errors_table = errors_function()
    return @errors_table

  -- hash of header params. keys should be a subset of OAUTH_ATTRIBUTE_KEYS.
  oauth_header_params: =>
    @oauth_header_params_table = luaoauth1.parse_authorization(@authorization()) unless @oauth_header_params_table
    @oauth_header_params_table

  -- raise a nice error message for a method that needs to be implemented on a module of config methods 
  config_method_not_implemented: (config_method) =>
    error("method #{config_method} must be implemented on a table of oauth config methods, which is given " ..
      "to luaoauth1.SignedRequest. Please consult the documentation.")

default_implementations = {
  timestamp_valid_past: =>
    if @config_methods['timestamp_valid_period']
      if type(@config_methods['timestamp_valid_period']) == 'function'
        @config_methods['timestamp_valid_period'](@)
      else
        @config_methods['timestamp_valid_period']
    else
      @config_method_not_implemented('timestamp_valid_period')
  timestamp_valid_future: =>
    if @config_methods['timestamp_valid_period']
      if type(@config_methods['timestamp_valid_period']) == 'function'
        @config_methods['timestamp_valid_period'](@)
      else
        @config_methods['timestamp_valid_period']
    else
      @config_method_not_implemented('timestamp_valid_period')
  allowed_signature_methods: =>
    return [k for k, v in pairs(SignableRequest.SIGNATURE_METHODS)]
  body_hash_required: =>
    false
}
for config_method in *{'timestamp_valid_period', 'timestamp_valid_past', 'timestamp_valid_future', 'allowed_signature_methods', 'consumer_secret', 'token_secret', 'is_nonce_used', 'use_nonce', 'token_belongs_to_consumer', 'body_hash_required'}
  SignedRequest.__base[config_method] = =>
    if @config_methods[config_method] != nil
      if type(@config_methods[config_method]) == 'function'
        @config_methods[config_method](@)
      else
        @config_methods[config_method]
    elseif default_implementations[config_method]
      default_implementations[config_method](@)
    else
      @config_method_not_implemented(config_method)

for key, _ in pairs(SignedRequest.ATTRIBUTE_KEYS)
  SignedRequest.__base[key] = =>
    @attributes[key]
  --SignedRequest.__base["has_#{key}"] = =>
  --  if type(@attributes[key]) == 'string'
  --    if @attributes[key]\find('%S')
  --      true
  --    else
  --      false
  --  else
  --    @attributes[key] != nil

for key, _ in pairs(SignedRequest.OAUTH_ATTRIBUTE_KEYS)
  SignedRequest.__base[key] = =>
    @oauth_header_params()["oauth_#{key}"]
  SignedRequest.__base["has_#{key}"] = =>
    value = @oauth_header_params()["oauth_#{key}"]
    if type(value) == 'string'
      if value\find('%S')
        true
      else
        false
    else
      value != nil

SignedRequest
