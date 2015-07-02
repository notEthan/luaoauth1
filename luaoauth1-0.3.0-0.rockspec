package = 'luaoauth1'
version = '0.3.0-0'
source = {
  url = 'git://github.com/notEthan/luaoauth1.git',
  tag = 'v0.3.0'
}
description = {
  summary = 'OAuth 1.0 in lua',
  detailed = [[
    OAuth 1.0 in lua
  ]],
  homepage = 'https://github.com/notEthan/luaoauth1',
  license = 'MIT <http://opensource.org/licenses/MIT>'
}
dependencies = {
  'lua >= 5.1',
}
build = {
  type = 'builtin',
  modules = {
    ['luaoauth1'] = 'luaoauth1.lua',
    ['luaoauth1.signable_request'] = 'luaoauth1/signable_request.lua',
    ['luaoauth1.signed_request'] = 'luaoauth1/signed_request.lua',
    ['luaoauth1.ngx_access'] = 'luaoauth1/ngx_access.lua',
    ['luaoauth1.socket.http'] = 'luaoauth1/socket/http.lua',
    ['luaoauth1.lapis.spec.server'] = 'luaoauth1/lapis/spec/server.lua',
  },
  install = {
  }
}
