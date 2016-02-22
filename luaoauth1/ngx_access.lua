local SignedRequest = require('luaoauth1.signed_request')
local luaoauth1 = require('luaoauth1')
if LUAOAUTH1_TEST_MODE then
  local real_os_time = os.time
  os.time = function()
    local redis_connection = require('redis').connect({
      host = "localhost",
      port = 6379
    })
    return tonumber(redis_connection:get('luaoauth1:os_time')) or real_os_time()
  end
end
return function(config_methods, options)
  if options == nil then
    options = { }
  end
  if options.bypass and options.bypass() then
    ngx.req.set_header("oauth.consumer_key", '')
    ngx.req.set_header("oauth.token", '')
    return ngx.req.set_header("oauth.authenticated", nil)
  else
    local authorization
    local content_type
    local scheme
    local port
    scheme = ngx.var.scheme
    port = ngx.var.server_port
    for k, v in pairs(ngx.req.get_headers()) do
      if k:lower() == 'authorization' then
        authorization = v
      end
      if k:lower() == 'content-type' then
        content_type = v
      end
      if (k:lower() == 'https' or k:lower() == 'http_x_forwarded_ssl') and v:lower() == 'on' then
        scheme = 'https'
      end
      if k:lower() == 'http_x_forwarded_scheme' or k:lower() == 'http_x_forwarded_proto' then
        scheme = v
      end
      if k:lower() == 'http-x-forwarded-port' then
        port = v
      end
    end
    ngx.req.read_body()
    local signed_request = SignedRequest({
      request_method = ngx.req.get_method(),
      uri = {
        scheme = scheme,
        host = ngx.var.host,
        port = port,
        request_uri = ngx.var.request_uri
      },
      media_type = luaoauth1.media_type(content_type),
      body = ngx.req.get_body_data() or false,
      authorization = authorization
    }, config_methods)
    local errors = signed_request:errors()
    if errors then
      if config_methods.on_error then
        config_methods.on_error(signed_request)
      end
      ngx.log(ngx.WARN, tostring(errors))
      local realm = options['realm'] or ''
      ngx.header["WWW-Authenticate"] = "OAuth realm=\"" .. tostring(realm) .. "\""
      ngx.header["Content-Type"] = "application/json"
      local body = {
        ['errors'] = errors
      }
      local error_values = { }
      for _, vs in pairs(errors) do
        for _index_0 = 1, #vs do
          local v = vs[_index_0]
          table.insert(error_values, v)
        end
      end
      local error_message
      if #error_values <= 1 then
        error_message = error_values[1]
      else
        local error_value_sentences
        do
          local _accum_0 = { }
          local _len_0 = 1
          for _index_0 = 1, #error_values do
            local v = error_values[_index_0]
            _accum_0[_len_0] = ((function()
              if v:find('%.%s*$') then
                return v
              else
                return v .. '.'
              end
            end)())
            _len_0 = _len_0 + 1
          end
          error_value_sentences = _accum_0
        end
        error_message = table.concat(error_value_sentences, ' ')
      end
      if error_message then
        body['error_message'] = error_message
      end
      ngx.status = ngx.HTTP_UNAUTHORIZED
      ngx.say(require('cjson').encode(body))
      return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    else
      if config_methods.on_success then
        config_methods.on_success(signed_request)
      end
      ngx.req.set_header("oauth.consumer_key", signed_request:consumer_key())
      ngx.req.set_header("oauth.token", signed_request:token())
      return ngx.req.set_header("oauth.authenticated", 'true')
    end
  end
end
