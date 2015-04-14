SignedRequest = require('luaoauth1/signed_request')

(config_methods, options = {}) ->

  if options.bypass and options.bypass()
    ngx.req.set_header("oauth.consumer_key", '')
    ngx.req.set_header("oauth.token", '')
    ngx.req.set_header("oauth.authenticated", nil)
  else
    local authorization
    local content_type
    inspect = require('inspect').inspect

    for k, v in pairs(ngx.req.get_headers())
      if k\lower() == 'authorization'
        authorization = v
      if k\lower() == 'content-type'
        content_type = v
    media_type = content_type -- TODO
    ngx.req.read_body()
    signed_request = SignedRequest({
      request_method: ngx.req.get_method(), -- or ngx.var.request_method ?
      uri: {
        scheme: ngx.var.scheme,
        host: ngx.var.host,
        port: ngx.var.server_port,
        request_uri: ngx.var.request_uri,
      },
      media_type: media_type or false,
      body: ngx.req.get_body_data() or false,
      authorization: authorization,
    }, config_methods)

    errors = signed_request\errors()
    if errors
      -- log unauthenticated request TODO
      ngx.log(ngx.WARN, require('inspect').inspect(errors))

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

      ngx.status = ngx.HTTP_FORBIDDEN
      ngx.say(require('cjson').encode(body))
      ngx.exit(ngx.HTTP_FORBIDDEN)
    else
      -- log authenticated request TODO
      ngx.req.set_header("oauth.consumer_key", signed_request\consumer_key())
      ngx.req.set_header("oauth.token", signed_request\token())
      ngx.req.set_header("oauth.authenticated", 'true')
