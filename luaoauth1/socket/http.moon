socket = {
  http: require("socket.http"),
  url: require("socket.url"),
}
SignableRequest = require('luaoauth1.signable_request')
luaoauth1 = require('luaoauth1')

request = (oauth, orig_request) ->
  request = {k, v for k, v in pairs(orig_request)}
  request.headers = {}
  if orig_request.headers
    for k, v in pairs(orig_request.headers)
      request.headers[k] = v
  socket_url = socket.url.parse(request.url)
  request_uri = if socket_url.query
    socket_url.path .. '?' .. socket_url.query
  else
    socket_url.path
  uri = {
    scheme: socket_url.scheme,
    host: socket_url.host,
    port: socket_url.port or (if socket_url.scheme == 'http' then 80 elseif socket_url.scheme == 'https' then 443),
    request_uri: request_uri,
  }

  media_type = false
  for k, v in pairs(request.headers)
    if k\lower() == 'content-type'
      media_type = luaoauth1.media_type(v)

  if not media_type and request.method
    request_method_lower = request.method\lower()
    for i, v in pairs({'post', 'put', 'patch', 'options'})
      if v == request_method_lower
        media_type = 'application/x-www-form-urlencoded' 

  body = false
  if request.source
    body_sink, body_table = ltn12.sink.table()
    ltn12.pump.all(request.source, body_sink)
    body = table.concat(body_table)
    request.source = ltn12.source.string(body)
  attrs = {
    request_method: request.method or 'get',
    uri: uri,
    media_type: media_type,
    body: body,
  }
  attrs[key] = val for key, val in pairs(oauth)
  loauath1_signable_request = SignableRequest(attrs)
  request.headers['authorization'] = loauath1_signable_request\authorization()
  -- work around broken host header in socket.http
  request.headers['host'] = string.gsub(socket_url.authority, "^.-@", "")
  return socket.http.request(request)

return {:request}
