local setmetatable = setmetatable

local exports = {}
local metatable = { __index = exports }

local crc32_max = 2^32 -1

local options_defaults = {
    token_length      = 32,
    cookie_name_token = 'ab-token',
    cookie_path       = '/',
    cookie_max_age    = nil, -- default cookie max age is to the and of browser session
    name_sticky       = 'ab-sticky',
    enable_sticky     = true,
}

---@param _nodes table
---@return table
---@return table
---@return table
local function prepare_nodes(_nodes)
    local node, nodes, ids, cumulative_weights, total_weight = "", {}, {}, {}, 0

    local id, data
    for id, data in pairs(_nodes) do
        if type(data[1]) == 'string' then
            nodes[id] = { data[1]:match( ("([^:]+):(.+)")) }
        elseif type(data[1]) == 'table' then
            nodes[id] = data[1]
        else
            ngx.log(ngx.ERR, 'node "'..id..'" contains invalid upstream value')
        end
        table.insert(ids, id)
        total_weight = total_weight + ( data[2] or 0 )
        table.insert(cumulative_weights, total_weight)
    end

    -- normalize cumulative weights to range 0..crc32_max
    for k,v in ipairs(cumulative_weights) do
        cumulative_weights[k] = v / total_weight * crc32_max
    end

    return nodes, ids, cumulative_weights
end

---@param options table
---@return table
local prepare_options = function(options)
    local _options = {}
    for k,v in pairs(options_defaults) do _options[k] = v end
    for k,v in pairs(options or {}) do _options[k] = v end
    return _options
end

---@param nodes_config table
---@param options table
local create = function(_, nodes_config, options)
    local nodes, ids, cumulative_weights = prepare_nodes(nodes_config)

    local self = {
        nodes              = nodes,
        ids                = ids,
        cumulative_weights = cumulative_weights,
        options            = prepare_options(options),
    }

    return setmetatable(self, metatable)
end

---@param length number
---@return string
local gen_token = function(length)
    local s, l = "", length
    repeat
        s = s .. ngx.md5(ngx.now() .. math.random(ngx.now()))
        l = l - 32
    until l < 0
    return s:sub(1,length)
end

---@param token string
---@param ids table
---@param cumulative_weights table
---@return string
local weighted_select = function(token, ids, cumulative_weights)
    local token_crc32 = ngx.crc32_short(token)

    for i, cw in ipairs(cumulative_weights) do
        if cw > token_crc32 then
            return ids[i]
        end
    end

    return nil
end

---@param name string
---@return string|nil
local get_cookie = function(name)
    local cookies = ngx.req.get_headers()["Cookie"]

    if type(cookies) ~= 'table' then
        cookies = { cookies }
    end

    for _, ch in ipairs(cookies) do
        for c in ch:gmatch(" ?([^;]+)") do
            local k,v = c:match('([^=]+)=(.*)')
            if k == name then
                return v
            end
        end
    end

    return nil
end

---@param name string
---@param value string
---@param path string
---@param max_age number|nil
local set_cookie = function(name, value, path, max_age)
    local cookie = name .. '=' .. value .. ';Path=' .. path
    if max_age ~= nil then
        cookie = cookie .. ';Max-Age=' .. max_age
    end

    local cookie_header = ngx.header['Set-Cookie'] or {}
    if type(cookie_header) ~= 'table' then
        cookie_header = {cookie_header}
    end
    table.insert(cookie_header, cookie)
    ngx.header['Set-Cookie'] = cookie_header
end

---@param self table
---@return string|nil
local select_by_sticky = function(self)
    local sticky_arg_value, sticky_cookie_value

    local args = ngx.req.get_uri_args()
    for key, values in pairs(args) do
        if key:lower() == self.options.name_sticky:lower() then
            if type(values) ~= 'table' then
                values = {values}
            end
            for _, value in ipairs(values) do
                if self.nodes[value] ~= nil then
                    sticky_arg_value = value
                else
                    sticky_arg_value = -1
                end
            end
            break
        end
    end

    if sticky_arg_value ~= nil and sticky_arg_value ~= -1 then
        ngx.log(ngx.NOTICE, 'found ab sticky arg: ', self.options.name_sticky, '=', sticky_arg_value)
    end

    sticky_cookie_value = get_cookie(self.options.name_sticky)

    if sticky_cookie_value ~= nil then
        if self.nodes[sticky_cookie_value] == nil then
            sticky_cookie_value = -1
        else
            ngx.log(ngx.NOTICE, 'found ab sticky cookie: ', self.options.name_sticky, '=', sticky_cookie_value)
        end
    end

    if sticky_arg_value == -1 or sticky_cookie_value == -1 then
        set_cookie(self.options.name_sticky, '', self.options.cookie_path, -1)
    end

    if sticky_arg_value == -1 then
        return nil
    end

    if sticky_arg_value ~= nil then
        set_cookie(self.options.name_sticky, sticky_arg_value, self.options.cookie_path, self.options.cookie_max_age)
        return sticky_arg_value
    end

    if sticky_cookie_value ~= nil then
        set_cookie(self.options.name_sticky, sticky_cookie_value, self.options.cookie_path, self.options.cookie_max_age)
        return sticky_cookie_value
    end

    return nil
end

---@private
---@param self table
---@return string|nil
local select_by_token = function(self)
    local token = get_cookie(self.options.cookie_name_token)

    if token ~= nil then
        token, _ = ngx.re.match(token, "^([a-z0-9]{".. self.options.token_length .."})$", "i")
        if token ~= nil then
            token = token[1]
        end
    end

    if token == nil then
        token = gen_token(self.options.token_length)
    end

    set_cookie(self.options.cookie_name_token, token, self.options.cookie_path, self.options.cookie_max_age)

    return weighted_select(token, self.ids, self.cumulative_weights)
end

---@param self table
---@return string
---@return string|number
local select = function(self)
    local node

    if self.options.enable_sticky then
        ngx.log(ngx.NOTICE, 'trying sticky arg and cookie')
        node = select_by_sticky(self)
        if node == nil then
            ngx.log(ngx.NOTICE, 'sticky arg or cookie not found')
        end
    end

    if node == nil then
        ngx.log(ngx.NOTICE, 'using token')
        node = select_by_token(self)
    end

    if node == nil then
        ngx.log(ngx.ERR, 'ACHTUNG!!! node by token was not selected')
        return nil, nil
    end

    return unpack(self.nodes[node])
end

-- EXPORTS --------------------------------------------------------------------
exports.create = create
exports.select = select

return exports