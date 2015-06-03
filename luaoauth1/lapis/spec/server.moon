lapis = {spec: {server: require('lapis.spec.server')}}

normalize_headers = require("lapis.spec.request").normalize_headers

server = {}

-- this function is copypasted from the lapis source, except to change 
-- the require and call to socket.http to use luaoauth1.socket.http. 
-- this is a bad thing - when the lapis implementation changes this will 
-- be out of date. but there is no way to intercept the request between
-- all the magic of this function and the call to socket.http, and extracting 
-- the oauth params from the given opts and then calling to the 
-- lapis.spec.server.request required from lapis.spec.server would be a major 
-- pain and in large part a reimplementation of what's already here anyway. 
server.request = (oauth, path="", opts={}) ->
  current_server = lapis.spec.server.get_current_server()
  unless current_server
    error "The test server is not loaded! (did you forget to load_test_server?)"

  http = require "luaoauth1.socket.http"

  headers = {}
  method = opts.method
  port = opts.port or current_server.app_port

  source = if data = opts.post or opts.data
    method or= "POST" if opts.post

    if type(data) == "table"
      headers["Content-type"] = "application/x-www-form-urlencoded"
      data = encode_query_string data

    headers["Content-length"] = #data
    ltn12.source.string(data)

  -- if the path is a url then extract host and path
  url_host, url_path = path\match "^https?://([^/]+)(.*)$"
  if url_host
    headers.Host = url_host
    path = url_path
    if override_port = url_host\match ":(%d+)$"
      port = override_port

  path = path\gsub "^/", ""

  -- merge get parameters
  if opts.get
    _, url_query = path\match "^(.-)%?(.*)$"
    get_params = if url_query
      parse_query_string url_query
    else
      {}

    for k,v in pairs opts.get
      get_params[k] = v

    path = path\gsub("^.-(%?.*)$", "") .. "?" .. encode_query_string get_params

  if opts.headers
    for k,v in pairs opts.headers
      headers[k] = v

  buffer = {}
  res, status, headers = http.request(oauth, {
    url: "http://127.0.0.1:#{port}/#{path}"
    redirect: false
    sink: ltn12.sink.table buffer
    :headers, :method, :source
  })

  assert res, status
  body = table.concat buffer

  headers = normalize_headers headers
  if headers.x_lapis_error
    json = require "cjson"
    {:status, :err, :trace} = json.decode body
    error "\n#{status}\n#{err}\n#{trace}"

  if opts.expect == "json"
    json = require "cjson"
    unless pcall -> body = json.decode body
      error "expected to get json from #{path}"

  status, body, headers

for k, v in pairs(lapis.spec.server)
  unless server[k]
    server[k] = v

return server
