local lpeg = require('lpeg')
local lpeg_locale = lpeg.locale()
local luaoauth1
luaoauth1 = {
  oauth_escape = function(unescaped)
    return string.gsub(unescaped, '([^A-Za-z0-9%-%.%_%~])', function(c)
      return string.format("%%%02X", string.byte(c))
    end)
  end,
  oauth_unescape = function(escaped)
    return string.gsub(escaped, "%%(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end)
  end,
  media_type = function(content_type)
    if type(content_type) == 'string' then
      local pos = content_type:find(';')
      if pos then
        return content_type:sub(1, pos - 1)
      else
        return content_type
      end
    else
      return false
    end
  end,
  parse_authorization = function(header)
    local authorization_match = lpeg.P({
      'authorization',
      space = lpeg_locale.space + lpeg.S("\n "),
      oauth_start = lpeg.S('Oo') * lpeg.S('Aa') * lpeg.S('Uu') * lpeg.S('Tt') * lpeg.S('Hh') * lpeg.V('space') ^ 1,
      key = lpeg.C(lpeg.R('az', 'AZ', '09', '__') ^ 1),
      value = lpeg.P('"') * lpeg.C((lpeg.P(1) - lpeg.P('"')) ^ 0) * lpeg.P('"'),
      keyvalue = lpeg.Cg(lpeg.V('key') * lpeg.P('=') * lpeg.V('value')),
      comma = lpeg.V('space') ^ 0 * ',' * lpeg.V('space') ^ 0,
      authorization = lpeg.V('oauth_start') * (lpeg.V('keyvalue') * lpeg.V('comma')) ^ 0 * (lpeg.V('keyvalue') * lpeg.V('space') ^ 0) ^ -1
    }) * -1
    local authorization_collect = lpeg.Cf(lpeg.Ct('') * authorization_match, function(t, k, v)
      k = luaoauth1.oauth_unescape(k)
      if not t[k] then
        t[k] = { }
      end
      table.insert(t[k], (luaoauth1.oauth_unescape(v)))
      return t
    end)
    local attributes = authorization_collect:match(header)
    if not (attributes) then
      error({
        type = 'luaoauth1.ParseError',
        errors = {
          Authorization = {
            "Could not parse Authorization header: " .. tostring(header)
          }
        }
      })
    end
    local duplicates
    do
      local _accum_0 = { }
      local _len_0 = 1
      for k, v in pairs(attributes) do
        if #attributes[k] > 1 then
          _accum_0[_len_0] = k
          _len_0 = _len_0 + 1
        end
      end
      duplicates = _accum_0
    end
    if #duplicates > 0 then
      error({
        type = 'luaoauth1.ParseError',
        errors = {
          Authorization = {
            "Received duplicate parameters: " .. tostring(table.concat(duplicates, ', '))
          }
        }
      })
    end
    local _tbl_0 = { }
    for k, v in pairs(attributes) do
      _tbl_0[k] = v[1]
    end
    return _tbl_0
  end
}
return luaoauth1
