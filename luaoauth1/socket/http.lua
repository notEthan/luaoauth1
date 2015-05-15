local socket = {
  http = require("socket.http"),
  url = require("socket.url")
}
local SignableRequest = require('luaoauth1.signable_request')
local luaoauth1 = require('luaoauth1')
local request
request = function(oauth, orig_request)
  do
    local _tbl_0 = { }
    for k, v in pairs(orig_request) do
      _tbl_0[k] = v
    end
    request = _tbl_0
  end
  if not (request.headers) then
    request.headers = { }
  end
  local socket_url = socket.url.parse(request.url)
  local request_uri
  if socket_url.query then
    request_uri = socket_url.path .. '?' .. socket_url.query
  else
    request_uri = socket_url.path
  end
  local uri = {
    scheme = socket_url.scheme,
    host = socket_url.host,
    port = socket_url.port or ((function()
      if socket_url.scheme == 'http' then
        return 80
      elseif socket_url.scheme == 'https' then
        return 443
      end
    end)()),
    request_uri = request_uri
  }
  local media_type
  media_type = false
  for k, v in pairs(request.headers) do
    if k:lower() == 'content-type' then
      media_type = luaoauth1.media_type(v)
    end
  end
  if not media_type and request.method then
    local request_method_lower = request.method:lower()
    for i, v in pairs({
      'post',
      'put',
      'patch',
      'options'
    }) do
      if v == request_method_lower then
        media_type = 'application/x-www-form-urlencoded'
      end
    end
  end
  local body
  body = false
  if request.source then
    local body_sink, body_table = ltn12.sink.table()
    ltn12.pump.all(request.source, body_sink)
    body = table.concat(body_table)
    request.source = ltn12.source.string(body)
  end
  local attrs = {
    request_method = request.method or 'get',
    uri = uri,
    media_type = media_type,
    body = body
  }
  for key, val in pairs(oauth) do
    attrs[key] = val
  end
  local loauath1_signable_request = SignableRequest(attrs)
  request.headers['authorization'] = loauath1_signable_request:authorization()
  return socket.http.request(request)
end
return {
  request = request
}
