local luaoauth1 = require('luaoauth1')
local crypto = require('crypto')
local encode_base64 = ngx and ngx.encode_base64 or require('mime').b64
local seed = 0
local bytes = io.open('/dev/urandom'):read(4)
for i = 1, bytes:len() do
  local byte = bytes:byte(i)
  for j = 1, (i - 1) * 8 do
    byte = byte * 2
  end
  seed = seed + byte
end
math.randomseed(seed)
local SignableRequest
do
  local _base_0 = {
    PROTOCOL_PARAM_KEYS = (function()
      local _tbl_0 = { }
      local _list_0 = {
        'consumer_key',
        'token',
        'signature_method',
        'timestamp',
        'nonce',
        'version'
      }
      for _index_0 = 1, #_list_0 do
        local k = _list_0[_index_0]
        _tbl_0[k] = true
      end
      return _tbl_0
    end)(),
    RECOGNIZED_KEYS = (function()
      local _tbl_0 = { }
      local _list_0 = {
        'authorization',
        'consumer_secret',
        'token_secret',
        'realm',
        'hash_body'
      }
      for _index_0 = 1, #_list_0 do
        local k = _list_0[_index_0]
        _tbl_0[k] = true
      end
      return _tbl_0
    end)(),
    SIGNATURE_METHODS = {
      ['RSA-SHA1'] = 'rsa_sha1_signature',
      ['HMAC-SHA1'] = 'hmac_sha1_signature',
      ['PLAINTEXT'] = 'plaintext_signature'
    },
    BODY_HASH_METHODS = {
      ['RSA-SHA1'] = 'sha1_body_hash',
      ['HMAC-SHA1'] = 'sha1_body_hash'
    },
    authorization = function(self)
      return "OAuth " .. tostring(self:normalized_protocol_params_string())
    end,
    signature = function(self)
      local sigmethod = SignableRequest.SIGNATURE_METHODS[self:signature_method()] or error("invalid signature method: " .. tostring(self:signature_method()))
      return self[sigmethod](self)
    end,
    body_hash = function(self)
      local hashmethod = SignableRequest.BODY_HASH_METHODS[self:signature_method()]
      if hashmethod then
        return self[hashmethod](self)
      end
    end,
    protocol_params = function(self)
      local _tbl_0 = { }
      for k, v in pairs(self.attributes['authorization']) do
        _tbl_0[k] = v
      end
      return _tbl_0
    end,
    signed_protocol_params = function(self)
      do
        local _with_0 = self:protocol_params()
        _with_0.oauth_signature = self:signature()
        return _with_0
      end
    end,
    is_form_encoded = function(self)
      local media_type = self.attributes['media_type']
      if type(media_type) == 'string' then
        media_type = media_type:lower()
      end
      return media_type == "application/x-www-form-urlencoded"
    end,
    signature_base = function(self)
      local parts = {
        self:normalized_request_method(),
        self:base_string_uri(),
        self:normalized_request_params_string()
      }
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #parts do
          local part = parts[_index_0]
          _accum_0[_len_0] = luaoauth1.oauth_escape(part)
          _len_0 = _len_0 + 1
        end
        parts = _accum_0
      end
      return table.concat(parts, '&')
    end,
    base_string_uri = function(self)
      local required
      do
        local _tbl_0 = { }
        local _list_0 = {
          'scheme',
          'host',
          'port',
          'request_uri'
        }
        for _index_0 = 1, #_list_0 do
          local k = _list_0[_index_0]
          _tbl_0[k] = true
        end
        required = _tbl_0
      end
      if not (type(self.attributes['uri']) == 'table') then
        error("uri must be given as a table with keys: " .. tostring(table.concat((function()
          local _accum_0 = { }
          local _len_0 = 1
          for k, _ in pairs(required) do
            _accum_0[_len_0] = k
            _len_0 = _len_0 + 1
          end
          return _accum_0
        end)(), ', ')))
      end
      local uri = self.attributes['uri']
      local missing
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k, _ in pairs(required) do
          if not uri[k] then
            _accum_0[_len_0] = k
            _len_0 = _len_0 + 1
          end
        end
        missing = _accum_0
      end
      if #missing > 0 then
        error("uri table is missing required keys: " .. tostring(table.concat(missing, ', ')))
      end
      local scheme = uri['scheme']:lower()
      local host = uri['host']:lower()
      local default_ports = {
        https = '443',
        http = '80'
      }
      local port
      if tostring(uri['port']) == default_ports[scheme] then
        port = ''
      else
        port = ":" .. tostring(uri['port'])
      end
      local request_uri = uri['request_uri']
      local fragment_start = request_uri:find('#', 1, true)
      if fragment_start then
        request_uri = request_uri:sub(1, fragment_start - 1)
      end
      local query_start = request_uri:find('?', 1, true)
      local path = request_uri:sub(1, (function()
        if query_start then
          return query_start - 1
        else
          return nil
        end
      end)())
      return tostring(scheme) .. "://" .. tostring(host) .. tostring(port) .. tostring(path)
    end,
    normalized_request_method = function(self)
      return self.attributes['request_method']:upper()
    end,
    normalized_request_params_string = function(self)
      local escaped
      do
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = self:normalized_request_params()
        for _index_0 = 1, #_list_0 do
          local param = _list_0[_index_0]
          do
            local _accum_1 = { }
            local _len_1 = 1
            for _index_1 = 1, #param do
              local x = param[_index_1]
              _accum_1[_len_1] = luaoauth1.oauth_escape(x)
              _len_1 = _len_1 + 1
            end
            _accum_0[_len_0] = _accum_1
          end
          _len_0 = _len_0 + 1
        end
        escaped = _accum_0
      end
      self:sort_params(escaped)
      return table.concat((function()
        local _accum_0 = { }
        local _len_0 = 1
        for i, e in ipairs(escaped) do
          _accum_0[_len_0] = table.concat(e, '=')
          _len_0 = _len_0 + 1
        end
        return _accum_0
      end)(), '&')
    end,
    normalized_request_params = function(self)
      local normalized_request_params = { }
      local _list_0 = self:query_params()
      for _index_0 = 1, #_list_0 do
        local e = _list_0[_index_0]
        table.insert(normalized_request_params, e)
      end
      for k, v in pairs(self:protocol_params()) do
        if not (k == 'realm' or k == 'oauth_signature') then
          table.insert(normalized_request_params, {
            k,
            v
          })
        end
      end
      local _list_1 = self:entity_params()
      for _index_0 = 1, #_list_1 do
        local e = _list_1[_index_0]
        table.insert(normalized_request_params, e)
      end
      return normalized_request_params
    end,
    query_params = function(self)
      local request_uri = self.attributes['uri']['request_uri']
      local query_start = request_uri:find('?', 1, true)
      if query_start then
        return self:parse_form_encoded(request_uri:sub(query_start + 1))
      else
        return { }
      end
    end,
    entity_params = function(self)
      if self:is_form_encoded() then
        return self:parse_form_encoded(self:body())
      else
        return { }
      end
    end,
    parse_form_encoded = function(self, data)
      local parsed = { }
      if not (data) then
        return parsed
      end
      local pos = 1
      local data_len = string.len(data)
      local seppos = string.find(data, '[&;]', pos) or data_len + 1
      while pos <= data_len and seppos do
        if seppos > pos then
          local pair_s = string.sub(data, pos, seppos - 1)
          local pair
          do
            do
              local eqpos = string.find(pair_s, '=', 1, true)
              if eqpos then
                if eqpos == 1 then
                  pair = nil
                else
                  pair = {
                    string.sub(pair_s, 1, eqpos - 1),
                    string.sub(pair_s, eqpos + 1)
                  }
                end
              else
                pair = {
                  pair_s,
                  ''
                }
              end
            end
          end
          if pair then
            table.insert(parsed, (function()
              local _accum_0 = { }
              local _len_0 = 1
              for _index_0 = 1, #pair do
                local v = pair[_index_0]
                _accum_0[_len_0] = luaoauth1.oauth_unescape(string.gsub(v, "+", " "))
                _len_0 = _len_0 + 1
              end
              return _accum_0
            end)())
          end
        end
        pos = seppos + 1
        seppos = string.find(data, '[&;]', pos) or data_len + 1
      end
      return parsed
    end,
    normalized_protocol_params_string = function(self)
      local sorted_params = self:sort_params(self:signed_protocol_params())
      local escaped_params
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k, v in pairs(sorted_params) do
          _accum_0[_len_0] = tostring(luaoauth1.oauth_escape(k)) .. "=\"" .. tostring(luaoauth1.oauth_escape(v)) .. "\""
          _len_0 = _len_0 + 1
        end
        escaped_params = _accum_0
      end
      return table.concat(escaped_params, ', ')
    end,
    body = function(self)
      return self.attributes['body'] or ''
    end,
    hash_body = function(self)
      if self:will_hash_body() then
        self.attributes['authorization']['oauth_body_hash'] = self:body_hash()
      end
    end,
    will_hash_body = function(self)
      return SignableRequest.BODY_HASH_METHODS[self:signature_method()] and not self:is_form_encoded() and self.attributes['hash_body'] ~= false
    end,
    signature_method = function(self)
      return self.attributes['authorization']['oauth_signature_method']
    end,
    rsa_sha1_signature = function(self)
      local pkey = crypto.pkey.from_pem(self.attributes['consumer_secret'], true) or error("Invalid RSA private key: " .. tostring(self.attributes['consumer_secret']))
      return (encode_base64(crypto.sign('sha1', self:signature_base(), pkey)))
    end,
    hmac_sha1_signature = function(self)
      local secret = self:plaintext_signature()
      return (encode_base64(crypto.hmac.digest('sha1', self:signature_base(), secret, true)))
    end,
    plaintext_signature = function(self)
      return table.concat((function()
        local _accum_0 = { }
        local _len_0 = 1
        local _list_0 = {
          'consumer_secret',
          'token_secret'
        }
        for _index_0 = 1, #_list_0 do
          local k = _list_0[_index_0]
          _accum_0[_len_0] = luaoauth1.oauth_escape(self.attributes[k] or '')
          _len_0 = _len_0 + 1
        end
        return _accum_0
      end)(), '&')
    end,
    sha1_body_hash = function(self)
      return (encode_base64(crypto.digest('sha1', self:body(), true)))
    end,
    sort_params = function(self, params)
      table.sort(params, function(a, b)
        local ak, av
        ak, av = a[1], a[2]
        local bk, bv
        bk, bv = b[1], b[2]
        if ak == bk then
          return av < bv
        else
          return ak < bk
        end
      end)
      return params
    end
  }
  _base_0.__index = _base_0
  local _class_0 = setmetatable({
    __init = function(self, attributes)
      if not (type(attributes) == 'table') then
        error("attributes must be a table")
      end
      do
        local _tbl_0 = { }
        for k, v in pairs(attributes) do
          _tbl_0[k] = v
        end
        self.attributes = _tbl_0
      end
      local required
      do
        local _tbl_0 = { }
        local _list_0 = {
          'request_method',
          'uri',
          'media_type',
          'body'
        }
        for _index_0 = 1, #_list_0 do
          local k = _list_0[_index_0]
          _tbl_0[k] = true
        end
        required = _tbl_0
      end
      if not (self.attributes['authorization']) then
        required['signature_method'] = true
        required['consumer_key'] = true
      end
      local missing
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k, _ in pairs(required) do
          if self.attributes[k] == nil then
            _accum_0[_len_0] = k
            _len_0 = _len_0 + 1
          end
        end
        missing = _accum_0
      end
      if #missing > 0 then
        error("missing required attributes: " .. tostring(table.concat(missing, ', ')))
      end
      local extra
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k, _ in pairs(self.attributes) do
          if not (required[k] or SignableRequest.PROTOCOL_PARAM_KEYS[k] or SignableRequest.RECOGNIZED_KEYS[k]) then
            _accum_0[_len_0] = k
            _len_0 = _len_0 + 1
          end
        end
        extra = _accum_0
      end
      if #extra > 0 then
        error("received unrecognized attributes: " .. tostring(table.concat(extra, ', ')) .. ". required = " .. tostring(table.concat((function()
          local _accum_0 = { }
          local _len_0 = 1
          for k, _ in pairs(required) do
            _accum_0[_len_0] = k
            _len_0 = _len_0 + 1
          end
          return _accum_0
        end)(), ',')))
      end
      if self.attributes['authorization'] then
        if not (type(self.attributes['authorization']) == 'table') then
          error("authorization must be a table")
        end
        local given_protocol_params
        do
          local _accum_0 = { }
          local _len_0 = 1
          for k, v in pairs(self.attributes) do
            if SignableRequest.PROTOCOL_PARAM_KEYS[k] and v then
              _accum_0[_len_0] = k
              _len_0 = _len_0 + 1
            end
          end
          given_protocol_params = _accum_0
        end
        if #given_protocol_params > 0 then
          return error("an existing authorization was given, but protocol parameters were also " .. "given. protocol parameters should not be specified when verifying an existing authorization. " .. "given protocol parameters were: " .. tostring(table.concat(given_protocol_params, ', ')))
        end
      else
        local defaults = {
          ['version'] = '1.0'
        }
        if self.attributes['signature_method'] ~= 'PLAINTEXT' then
          defaults['nonce'] = table.concat((function()
            local _accum_0 = { }
            local _len_0 = 1
            for i = 1, 16 do
              _accum_0[_len_0] = string.format("%02X", math.random(256) - 1)
              _len_0 = _len_0 + 1
            end
            return _accum_0
          end)())
          defaults['timestamp'] = tostring(os.time())
        end
        self.attributes['authorization'] = { }
        for key, _ in pairs(SignableRequest.PROTOCOL_PARAM_KEYS) do
          do
            self.attributes['authorization']["oauth_" .. tostring(key)] = self.attributes[key] or ((function()
              if self.attributes[key] == false then
                return nil
              else
                return defaults[key]
              end
            end)())
          end
        end
        if self.attributes['realm'] ~= nil then
          self.attributes['authorization']['realm'] = self.attributes['realm']
        end
        return self:hash_body()
      end
    end,
    __base = _base_0,
    __name = "SignableRequest"
  }, {
    __index = _base_0,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  SignableRequest = _class_0
end
return SignableRequest
