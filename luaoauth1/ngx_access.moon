SignedRequest = require('luaoauth1.signed_request')
luaoauth1 = require('luaoauth1')

if LUAOAUTH1_TEST_MODE
  -- stub os.time so that the tests can time travel 
  real_os_time = os.time
  os.time = ->
    redis_connection = require('redis').connect({host: "localhost", port: 6379})
    tonumber(redis_connection\get('luaoauth1:os_time')) or real_os_time()

(config_methods, options = {}) ->

  if options.bypass and options.bypass()
    ngx.req.set_header("oauth.consumer_key", '')
    ngx.req.set_header("oauth.token", '')
    ngx.req.set_header("oauth.authenticated", nil)
  else
    local authorization
    local content_type
    local scheme
    scheme = ngx.var.scheme
    for k, v in pairs(ngx.req.get_headers())
      if k\lower() == 'authorization'
        authorization = v
      if k\lower() == 'content-type'
        content_type = v
      if (k\lower() == 'https' or k\lower() == 'http_x_forwarded_ssl') and v\lower() == 'on'
        scheme = 'https'
      if k\lower() == 'http_x_forwarded_scheme' or k\lower() == 'http_x_forwarded_proto'
        scheme = v
    ngx.req.read_body()
    signed_request = SignedRequest({
      request_method: ngx.req.get_method(), -- or ngx.var.request_method ?
      uri: {
        scheme: scheme,
        host: ngx.var.host,
        port: ngx.var.server_port,
        request_uri: ngx.var.request_uri,
      },
      media_type: luaoauth1.media_type(content_type),
      body: ngx.req.get_body_data() or false,
      authorization: authorization,
    }, config_methods)

    errors = signed_request\errors()
    if errors
      if config_methods.on_error
        config_methods.on_error(signed_request)

      -- log unauthenticated request TODO
      ngx.log(ngx.WARN, tostring(errors))

      realm = options['realm'] or ''
      ngx.header["WWW-Authenticate"] = "OAuth realm=\"#{realm}\""
      ngx.header["Content-Type"] = "application/json"

      body = {'errors': errors}
      error_values = {}
      for _, vs in pairs(errors)
        for v in *vs
          table.insert(error_values, v)

      error_message = if #error_values <= 1
        error_values[1]
      else
        -- sentencify with periods 
        error_value_sentences = [(if v\find('%.%s*$') then v else v .. '.') for v in *error_values]
        table.concat(error_value_sentences, ' ')

      body['error_message'] = error_message if error_message

      ngx.status = ngx.HTTP_UNAUTHORIZED
      ngx.say(require('cjson').encode(body))
      ngx.exit(ngx.HTTP_UNAUTHORIZED)
    else
      if config_methods.on_success
        config_methods.on_success(signed_request)

      -- log authenticated request TODO
      ngx.req.set_header("oauth.consumer_key", signed_request\consumer_key())
      ngx.req.set_header("oauth.token", signed_request\token())
      ngx.req.set_header("oauth.authenticated", 'true')
