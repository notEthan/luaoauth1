lpeg = require('lpeg')
lpeg_locale = lpeg.locale()

local luaoauth1
luaoauth1 = {
  oauth_escape: (unescaped) ->
    string.gsub(unescaped, '([^A-Za-z0-9%-%.%_%~])', (c) -> string.format("%%%02X", string.byte(c)))

  -- does not convert '+' to ' '
  oauth_unescape: (escaped) ->
    string.gsub(escaped, "%%(%x%x)", (h) -> string.char(tonumber(h, 16)))

  parse_authorization: (header) ->
    authorization_match = lpeg.P({
      'authorization',
      space: lpeg_locale.space + lpeg.S("\n ")
      oauth_start: lpeg.P('OAuth') * lpeg.V('space')^1,
      key: lpeg.C(lpeg.R('az', 'AZ', '09', '__')^1),
      value: lpeg.P('"') * lpeg.C((lpeg.P(1) - lpeg.P('"'))^0) * lpeg.P('"'),
      keyvalue: lpeg.Cg(lpeg.V('key') * lpeg.P('=') * lpeg.V('value')),
      comma: lpeg.V('space')^0 * ',' * lpeg.V('space')^0,
      authorization: lpeg.V('oauth_start') * (lpeg.V('keyvalue') * lpeg.V('comma'))^0 * (lpeg.V('keyvalue') * lpeg.V('space')^0)^-1
    }) * -1
    authorization_collect = lpeg.Cf(lpeg.Ct('') * authorization_match, (t, k, v) ->
      k = luaoauth1.oauth_unescape(k)
      t[k] = {} if not t[k]
      table.insert(t[k], (luaoauth1.oauth_unescape(v)))
      t
    )
    attributes = authorization_collect\match(header)

    unless attributes
      error({type: 'luaoauth1.ParseError', errors: {Authorization: {"Could not parse Authorization header: #{header}"}}})

    duplicates = [k for k, v in pairs(attributes) when #attributes[k] > 1]
    if #duplicates > 0
      error({type: 'luaoauth1.ParseError', errors: {Authorization: {"Received duplicate parameters: #{table.concat(duplicates, ', ')}"}}})

    return {k, v[1] for k, v in pairs(attributes)}
}
luaoauth1
