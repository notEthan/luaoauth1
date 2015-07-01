local luaoauth1 = require('luaoauth1')
local SignableRequest = require('luaoauth1.signable_request')
local SignedRequest
do
  local _base_0 = {
    ATTRIBUTE_KEYS = (function()
      local _tbl_0 = { }
      local _list_0 = {
        'request_method',
        'uri',
        'body',
        'media_type',
        'authorization'
      }
      for _index_0 = 1, #_list_0 do
        local k = _list_0[_index_0]
        _tbl_0[k] = true
      end
      return _tbl_0
    end)(),
    OAUTH_ATTRIBUTE_KEYS = (function()
      local keys
      do
        local _tbl_0 = { }
        for k, v in pairs(SignableRequest.PROTOCOL_PARAM_KEYS) do
          _tbl_0[k] = v
        end
        keys = _tbl_0
      end
      local _list_0 = {
        'signature',
        'body_hash'
      }
      for _index_0 = 1, #_list_0 do
        local key = _list_0[_index_0]
        keys[key] = true
      end
      return keys
    end)(),
    errors = function(self)
      if self.errors_table ~= nil then
        return self.errors_table
      end
      local errors_function
      errors_function = function()
        if self:authorization() == nil then
          return ({
            Authorization = {
              "Authorization header is missing"
            }
          })
        elseif not self:authorization():find('%S') then
          return ({
            Authorization = {
              "Authorization header is blank"
            }
          })
        end
        local ok, parse_exception = pcall(function()
          return self:oauth_header_params()
        end)
        if not ok then
          if type(parse_exception) == 'table' and parse_exception.errors then
            return parse_exception.errors
          else
            error(parse_exception)
          end
        end
        local errors = { }
        local add_error
        add_error = function(key, message)
          if not errors[key] then
            errors[key] = { }
          end
          return table.insert(errors[key], message)
        end
        if not self:has_timestamp() then
          if not (self:signature_method() == 'PLAINTEXT') then
            add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is missing")
          end
        elseif not self:timestamp():find('^%s*%d+%s*$') then
          add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is not an integer - got: " .. tostring(self:timestamp()))
        else
          local timestamp_i = tonumber(self:timestamp())
          if timestamp_i < os.time() - self:timestamp_valid_past() then
            add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is too old: " .. tostring(self:timestamp()))
          elseif timestamp_i > os.time() + self:timestamp_valid_future() then
            add_error('Authorization oauth_timestamp', "Authorization oauth_timestamp is too far in the future: " .. tostring(self:timestamp()))
          end
        end
        if self:has_version() and self:version() ~= '1.0' then
          add_error('Authorization oauth_version', "Authorization oauth_version must be 1.0; got: " .. tostring(self:version()))
        end
        local secrets = { }
        if not self:has_consumer_key() then
          add_error('Authorization oauth_consumer_key', "Authorization oauth_consumer_key is missing")
        else
          secrets['consumer_secret'] = self:consumer_secret()
          if not secrets['consumer_secret'] then
            add_error('Authorization oauth_consumer_key', 'Authorization oauth_consumer_key is invalid')
          end
        end
        if self:has_token() then
          secrets['token_secret'] = self:token_secret()
          if not secrets['token_secret'] then
            add_error('Authorization oauth_token', 'Authorization oauth_token is invalid')
          elseif not self:token_belongs_to_consumer() then
            add_error('Authorization oauth_token', 'Authorization oauth_token does not belong to the specified consumer')
          end
        end
        if not self:has_nonce() then
          if not (self:signature_method() == 'PLAINTEXT') then
            add_error('Authorization oauth_nonce', "Authorization oauth_nonce is missing")
          end
        elseif self:is_nonce_used() then
          add_error('Authorization oauth_nonce', "Authorization oauth_nonce has already been used")
        end
        if not self:has_signature_method() then
          add_error('Authorization oauth_signature_method', "Authorization oauth_signature_method is missing")
        else
          local allowed_signature_method = false
          local _list_0 = self:allowed_signature_methods()
          for _index_0 = 1, #_list_0 do
            local sm = _list_0[_index_0]
            if self:signature_method():lower() == sm:lower() then
              allowed_signature_method = true
            end
          end
          if not (allowed_signature_method) then
            add_error('Authorization oauth_signature_method', "Authorization oauth_signature_method must be one of " .. tostring(table.concat(self:allowed_signature_methods(), ', ')) .. "; got: " .. tostring(self:signature_method()))
          end
        end
        if not self:has_signature() then
          add_error('Authorization oauth_signature', "Authorization oauth_signature is missing")
        end
        local sr_attributes
        do
          local _tbl_0 = { }
          for k, v in pairs(self.attributes) do
            _tbl_0[k] = v
          end
          sr_attributes = _tbl_0
        end
        for k, v in pairs(secrets) do
          sr_attributes[k] = v
        end
        sr_attributes['authorization'] = self:oauth_header_params()
        local signable_request = SignableRequest(sr_attributes)
        if self:has_body_hash() then
          if not signable_request:is_form_encoded() then
            local has_key = false
            for k, _ in pairs(SignableRequest.BODY_HASH_METHODS) do
              if k == self:signature_method() then
                has_key = true
              end
            end
            if has_key then
              if self:body_hash() == signable_request:body_hash() then
                local _ = nil
              else
                add_error('Authorization oauth_body_hash', "Authorization oauth_body_hash is invalid")
              end
            else
              local _ = nil
            end
          else
            add_error('Authorization oauth_body_hash', "Authorization oauth_body_hash must not be included with form-encoded requests")
          end
        else
          if not signable_request:is_form_encoded() then
            if self:body_hash_required() then
              add_error('Authorization oauth_body_hash', "Authorization oauth_body_hash is required (on non-form-encoded requests)")
            else
              local _ = nil
            end
          else
            local _ = nil
          end
        end
        if next(errors) ~= nil then
          return (errors)
        end
        if not (self:signature() == signable_request:signature()) then
          return ({
            ['Authorization oauth_signature'] = {
              "Authorization oauth_signature is invalid"
            }
          })
        end
        if self:has_nonce() then
          local exception
          ok, exception = xpcall((function()
            return self:use_nonce()
          end), function(exception)
            if type(exception) == 'table' and exception.type == 'luaoauth1.NonceUsedError' then
              return exception
            else
              return {
                exception = exception,
                traceback = debug.traceback()
              }
            end
          end)
          if not ok then
            if type(exception) == 'table' and exception.type == 'luaoauth1.NonceUsedError' then
              return ({
                ['Authorization oauth_nonce'] = {
                  'Authorization oauth_nonce has already been used'
                }
              })
            else
              if type(exception.exception) == 'string' then
                error(exception.exception .. "\noriginal traceback:\n" .. exception.traceback)
              elseif type(exception.exception) == 'table' then
                exception.exception.original_traceback = exception.traceback
                error(exception.exception)
              else
                error(exception.exception)
              end
            end
          end
        end
        return false
      end
      self.errors_table = errors_function()
      return self.errors_table
    end,
    oauth_header_params = function(self)
      if not (self.oauth_header_params_table) then
        self.oauth_header_params_table = luaoauth1.parse_authorization(self:authorization())
      end
      return self.oauth_header_params_table
    end,
    config_method_not_implemented = function(self, config_method)
      return error("method " .. tostring(config_method) .. " must be implemented on a table of oauth config methods, which is given " .. "to luaoauth1.SignedRequest. Please consult the documentation.")
    end
  }
  _base_0.__index = _base_0
  local _class_0 = setmetatable({
    __init = function(self, attributes, config_methods)
      if not (type(attributes) == 'table') then
        error("attributes must be a table")
      end
      if not (type(config_methods) == 'table') then
        error("config_methods must be a table")
      end
      do
        local _tbl_0 = { }
        for k, v in pairs(attributes) do
          _tbl_0[k] = v
        end
        self.attributes = _tbl_0
      end
      local extra
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k, _ in pairs(self.attributes) do
          if not SignedRequest.ATTRIBUTE_KEYS[k] then
            _accum_0[_len_0] = k
            _len_0 = _len_0 + 1
          end
        end
        extra = _accum_0
      end
      if #extra > 0 then
        error("received unrecognized attributes: " .. tostring(table.concat(extra, ', ')))
      end
      self.config_methods = config_methods
    end,
    __base = _base_0,
    __name = "SignedRequest"
  }, {
    __index = _base_0,
    __call = function(cls, ...)
      local _self_0 = setmetatable({}, _base_0)
      cls.__init(_self_0, ...)
      return _self_0
    end
  })
  _base_0.__class = _class_0
  SignedRequest = _class_0
end
local default_implementations = {
  timestamp_valid_past = function(self)
    if self.config_methods['timestamp_valid_period'] then
      if type(self.config_methods['timestamp_valid_period']) == 'function' then
        return self.config_methods['timestamp_valid_period'](self)
      else
        return self.config_methods['timestamp_valid_period']
      end
    else
      return self:config_method_not_implemented('timestamp_valid_period')
    end
  end,
  timestamp_valid_future = function(self)
    if self.config_methods['timestamp_valid_period'] then
      if type(self.config_methods['timestamp_valid_period']) == 'function' then
        return self.config_methods['timestamp_valid_period'](self)
      else
        return self.config_methods['timestamp_valid_period']
      end
    else
      return self:config_method_not_implemented('timestamp_valid_period')
    end
  end,
  allowed_signature_methods = function(self)
    local _accum_0 = { }
    local _len_0 = 1
    for k, v in pairs(SignableRequest.SIGNATURE_METHODS) do
      _accum_0[_len_0] = k
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end,
  body_hash_required = function(self)
    return false
  end
}
local _list_0 = {
  'timestamp_valid_period',
  'timestamp_valid_past',
  'timestamp_valid_future',
  'allowed_signature_methods',
  'consumer_secret',
  'token_secret',
  'is_nonce_used',
  'use_nonce',
  'token_belongs_to_consumer',
  'body_hash_required'
}
for _index_0 = 1, #_list_0 do
  local config_method = _list_0[_index_0]
  SignedRequest.__base[config_method] = function(self)
    if self.config_methods[config_method] ~= nil then
      if type(self.config_methods[config_method]) == 'function' then
        return self.config_methods[config_method](self)
      else
        return self.config_methods[config_method]
      end
    elseif default_implementations[config_method] then
      return default_implementations[config_method](self)
    else
      return self:config_method_not_implemented(config_method)
    end
  end
end
for key, _ in pairs(SignedRequest.ATTRIBUTE_KEYS) do
  SignedRequest.__base[key] = function(self)
    return self.attributes[key]
  end
end
for key, _ in pairs(SignedRequest.OAUTH_ATTRIBUTE_KEYS) do
  SignedRequest.__base[key] = function(self)
    return self:oauth_header_params()["oauth_" .. tostring(key)]
  end
  SignedRequest.__base["has_" .. tostring(key)] = function(self)
    local value = self:oauth_header_params()["oauth_" .. tostring(key)]
    if type(value) == 'string' then
      if value:find('%S') then
        return true
      else
        return false
      end
    else
      return value ~= nil
    end
  end
end
return SignedRequest
