local _M = {
  _VERSION = '0.1.1'
}

local http = require("resty.http")
local cjson = require("cjson")

Routers = {}
Routers_Loaded = false

local function parse_toml(toml, options)
	options = options or {}
	local strict = (options.strict ~= nil and options.strict or TOML.strict)

	-- the official TOML definition of whitespace
	local ws = "[\009\032]"

	-- the official TOML definition of newline
	local nl = "[\10"
	do
		local crlf = {string.char(224), string.char(180), string.char(138)}
		nl = nl .. table.concat(crlf)
	end
	nl = nl .. "]"
	
	-- stores text data
	local buffer = ""

	-- the current location within the string to parse
	local cursor = 1

	-- the output table
	local out = {}

	-- the current table to write to
	local obj = out

	-- returns the next n characters from the current position
	local function char(n)
		n = n or 0
		return toml:sub(cursor + n, cursor + n)
	end

	-- moves the current position forward n (default: 1) characters
	local function step(n)
		n = n or 1
		cursor = cursor + n
	end

	-- move forward until the next non-whitespace character
	local function skipWhitespace()
		while(char():match(ws)) do
			step()
		end
	end

	-- remove the (Lua) whitespace at the beginning and end of a string
	local function trim(str)
		return str:gsub("^%s*(.-)%s*$", "%1")
	end

	-- divide a string into a table around a delimiter
	local function split(str, delim)
		if str == "" then return {} end
		local result = {}
		local append = delim
		if delim:match("%%") then
			append = delim:gsub("%%", "")
		end
		for match in (str .. append):gmatch("(.-)" .. delim) do
			table.insert(result, match)
		end
		return result
	end

	-- produce a parsing error message
	-- the error contains the line number of the current position
	local function err(message, strictOnly)
		if not strictOnly or (strictOnly and strict) then
			local line = 1
			local c = 0
			for l in toml:gmatch("(.-)" .. nl) do
				c = c + l:len()
				if c >= cursor then
					break
				end
				line = line + 1
			end
			error("TOML: " .. message .. " on line " .. line .. ".", 4)
		end
	end

	-- prevent infinite loops by checking whether the cursor is
	-- at the end of the document or not
	local function bounds()
		return cursor <= toml:len()
	end

	local function parseString()
		local quoteType = char() -- should be single or double quote

		-- this is a multiline string if the next 2 characters match
		local multiline = (char(1) == char(2) and char(1) == char())

		-- buffer to hold the string
		local str = ""

		-- skip the quotes
		step(multiline and 3 or 1)

		while(bounds()) do
			if multiline and char():match(nl) and str == "" then
				-- skip line break line at the beginning of multiline string
				step()
			end

			-- keep going until we encounter the quote character again
			if char() == quoteType then
				if multiline then
					if char(1) == char(2) and char(1) == quoteType then
						step(3)
						break
					end
				else
					step()
					break
				end
			end

			if char():match(nl) and not multiline then
				err("Single-line string cannot contain line break")
			end

			-- if we're in a double-quoted string, watch for escape characters!
			if quoteType == '"' and char() == "\\" then
				if multiline and char(1):match(nl) then
					-- skip until first non-whitespace character
					step(1) -- go past the line break
					while(bounds()) do
						if not char():match(ws) and not char():match(nl) then
							break
						end
						step()
					end
				else
					-- all available escape characters
					local escape = {
						b = "\b",
						t = "\t",
						n = "\n",
						f = "\f",
						r = "\r",
						['"'] = '"',
						["\\"] = "\\",
					}
					-- utf function from http://stackoverflow.com/a/26071044
					-- converts \uXXX into actual unicode
					local function utf(char)
						local bytemarkers = {{0x7ff, 192}, {0xffff, 224}, {0x1fffff, 240}}
						if char < 128 then return string.char(char) end
						local charbytes = {}
						for bytes, vals in pairs(bytemarkers) do
							if char <= vals[1] then
								for b = bytes + 1, 2, -1 do
									local mod = char % 64
									char = (char - mod) / 64
									charbytes[b] = string.char(128 + mod)
								end
								charbytes[1] = string.char(vals[2] + char)
								break
							end
						end
						return table.concat(charbytes)
					end

					if escape[char(1)] then
						-- normal escape
						str = str .. escape[char(1)]
						step(2) -- go past backslash and the character
					elseif char(1) == "u" then
						-- utf-16
						step()
						local uni = char(1) .. char(2) .. char(3) .. char(4)
						step(5)
						uni = tonumber(uni, 16)
						if (uni >= 0 and uni <= 0xd7ff) and not (uni >= 0xe000 and uni <= 0x10ffff) then
							str = str .. utf(uni)
						else
							err("Unicode escape is not a Unicode scalar")
						end
					elseif char(1) == "U" then
						-- utf-32
						step()
						local uni = char(1) .. char(2) .. char(3) .. char(4) .. char(5) .. char(6) .. char(7) .. char(8)
						step(9)
						uni = tonumber(uni, 16)
						if (uni >= 0 and uni <= 0xd7ff) and not (uni >= 0xe000 and uni <= 0x10ffff) then
							str = str .. utf(uni)
						else
							err("Unicode escape is not a Unicode scalar")
						end
					else
						err("Invalid escape")
					end
				end
			else
				-- if we're not in a double-quoted string, just append it to our buffer raw and keep going
				str = str .. char()
				step()
			end
		end

		return {value = str, type = "string"}
	end

	local function parseNumber()
		local num = ""
		local exp
		local date = false
		while(bounds()) do
			if char():match("[%+%-%.eE_0-9]") then
				if not exp then
					if char():lower() == "e" then
						-- as soon as we reach e or E, start appending to exponent buffer instead of
						-- number buffer
						exp = ""
					elseif char() ~= "_" then
						num = num .. char()
					end
				elseif char():match("[%+%-0-9]") then
					exp = exp .. char()
				else
					err("Invalid exponent")
				end
			elseif char():match(ws) or char() == "#" or char():match(nl) or char() == "," or char() == "]" or char() == "}" then
				break
			elseif char() == "T" or char() == "Z" then
				-- parse the date (as a string, since lua has no date object)
				date = true
				while(bounds()) do
					if char() == "," or char() == "]" or char() == "#" or char():match(nl) or char():match(ws) then
						break
					end
					num = num .. char()
					step()
				end
			else
				err("Invalid number")
			end
			step()
		end

		if date then
			return {value = num, type = "date"}
		end

		local float = false
		if num:match("%.") then float = true end

		exp = exp and tonumber(exp) or 0
		num = tonumber(num)

		if not float then
			return {
				-- lua will automatically convert the result
				-- of a power operation to a float, so we have
				-- to convert it back to an int with math.floor
				value = math.floor(num * 10^exp),
				type = "int",
			}
		end

		return {value = num * 10^exp, type = "float"}
	end

	local parseArray, getValue
	
	function parseArray()
		step() -- skip [
		skipWhitespace()

		local arrayType
		local array = {}

		while(bounds()) do
			if char() == "]" then
				break
			elseif char():match(nl) then
				-- skip
				step()
				skipWhitespace()
			elseif char() == "#" then
				while(bounds() and not char():match(nl)) do
					step()
				end
			else
				-- get the next object in the array
				local v = getValue()
				if not v then break end

				-- set the type if it hasn't been set before
				if arrayType == nil then
					arrayType = v.type
				elseif arrayType ~= v.type then
					err("Mixed types in array", true)
				end

				array = array or {}
				table.insert(array, v.value)
				
				if char() == "," then
					step()
				end
				skipWhitespace()
			end
		end
		step()

		return {value = array, type = "array"}
	end

	local function parseInlineTable()
		step() -- skip opening brace

		local buffer = ""
		local quoted = false
		local tbl = {}

		while bounds() do
			if char() == "}" then
				break
			elseif char() == "'" or char() == '"' then
				buffer = parseString().value
				quoted = true
			elseif char() == "=" then
				if not quoted then
					buffer = trim(buffer)
				end

				step() -- skip =
				skipWhitespace()

				if char():match(nl) then
					err("Newline in inline table")
				end

				local v = getValue().value
				tbl[buffer] = v

				skipWhitespace()

				if char() == "," then
					step()
				elseif char():match(nl) then
					err("Newline in inline table")
				end

				quoted = false
				buffer = ""
			else
				buffer = buffer .. char()
				step()
			end
		end
		step() -- skip closing brace

		return {value = tbl, type = "array"}
	end

	local function parseBoolean()
		local v
		if toml:sub(cursor, cursor + 3) == "true" then
			step(4)
			v = {value = true, type = "boolean"}
		elseif toml:sub(cursor, cursor + 4) == "false" then
			step(5)
			v = {value = false, type = "boolean"}
		else
			err("Invalid primitive")
		end

		skipWhitespace()
		if char() == "#" then
			while(not char():match(nl)) do
				step()
			end
		end

		return v
	end

	-- figure out the type and get the next value in the document
	function getValue()
		if char() == '"' or char() == "'" then
			return parseString()
		elseif char():match("[%+%-0-9]") then
			return parseNumber()
		elseif char() == "[" then
			return parseArray()
		elseif char() == "{" then
			return parseInlineTable()
		else
			return parseBoolean()
		end
		-- date regex (for possible future support):
		-- %d%d%d%d%-[0-1][0-9]%-[0-3][0-9]T[0-2][0-9]%:[0-6][0-9]%:[0-6][0-9][Z%:%+%-%.0-9]*
	end

	-- track whether the current key was quoted or not
	local quotedKey = false
	
	-- parse the document!
	while(cursor <= toml:len()) do

		-- skip comments and whitespace
		if char() == "#" then
			while(not char():match(nl)) do
				step()
			end
		end

		if char():match(nl) then
			-- skip
		end

		if char() == "=" then
			step()
			skipWhitespace()
			
			-- trim key name
			buffer = trim(buffer)

			if buffer:match("^[0-9]*$") and not quotedKey then
				buffer = tonumber(buffer)
			end

			if buffer == "" and not quotedKey then
				err("Empty key name")
			end

			local v = getValue()
			if v then
				-- if the key already exists in the current object, throw an error
				if obj[buffer] then
					err('Cannot redefine key "' .. buffer .. '"', true)
				end
				obj[buffer] = v.value
			end

			-- clear the buffer
			buffer = ""
			quotedKey = false

			-- skip whitespace and comments
			skipWhitespace()
			if char() == "#" then
				while(bounds() and not char():match(nl)) do
					step()
				end
			end

			-- if there is anything left on this line after parsing a key and its value,
			-- throw an error
			if not char():match(nl) and cursor < toml:len() then
				err("Invalid primitive")
			end
		elseif char() == "[" then
			buffer = ""
			step()
			local tableArray = false

			-- if there are two brackets in a row, it's a table array!
			if char() == "[" then
				tableArray = true
				step()
			end

			obj = out

			local function processKey(isLast)
				isLast = isLast or false
				buffer = trim(buffer)

				if not quotedKey and buffer == "" then
					err("Empty table name")
				end

				if isLast and obj[buffer] and not tableArray and #obj[buffer] > 0 then
					err("Cannot redefine table", true)
				end

				-- set obj to the appropriate table so we can start
				-- filling it with values!
				if tableArray then
					-- push onto cache
					if obj[buffer] then
						obj = obj[buffer]
						if isLast then
							table.insert(obj, {})
						end
						obj = obj[#obj]
					else
						obj[buffer] = {}
						obj = obj[buffer]
						if isLast then
							table.insert(obj, {})
							obj = obj[1]
						end
					end
				else
					obj[buffer] = obj[buffer] or {}
					obj = obj[buffer]
				end
			end

			while(bounds()) do
				if char() == "]" then
					if tableArray then
						if char(1) ~= "]" then
							err("Mismatching brackets")
						else
							step() -- skip inside bracket
						end
					end
					step() -- skip outside bracket

					processKey(true)
					buffer = ""
					break
				elseif char() == '"' or char() == "'" then
					buffer = parseString().value
					quotedKey = true
				elseif char() == "." then
					step() -- skip period
					processKey()
					buffer = ""
				else
					buffer = buffer .. char()
					step()
				end
			end

			buffer = ""
			quotedKey = false
		elseif (char() == '"' or char() == "'") then
			-- quoted key
			buffer = parseString().value
			quotedKey = true
		end

		buffer = buffer .. (char():match(nl) and "" or char())
		step()
	end

	return out
end

function _M.load_rules(toml_path)
    if Routers_Loaded then
        return
    end
    Routers_Loaded = true

    local config_file = io.open(toml_path, "r")
    if not config_file then
        ngx.log(ngx.ERR, "Failed to open config file " .. toml_path)
        return
    end

    local config_content = config_file:read("*a")
    config_file:close()

    Routers = toml.parse(config_content)
end

function _M.proxy_pass(uri)
    local route = Routers[uri]
    if not route then
        return
    end
    local type = route["type"]
    local backend_url = route["backend_url"] or ""
    local callback_url = route["callback_url"] or ""
    local callback_credentials_header = route["callback_credentials_header"] or "X-Callback-Credentials"
    local timeout_ms = route["timeout_ms"] or 0
    local resp_body = route["resp_body"] or ""
    local content_type = route["content_type"] or "application/json; charset=utf-8"
    local status_code = route["status_code"] or 200

    if backend_url == "" then
        ngx.log(ngx.ERR, "No backend URL specified for route ", uri)
        return
    end

    if resp_body == "" then
        ngx.log(ngx.ERR, "No response body specified for route ", uri)
        return
    end

    if type == "callback" and callback_url == "" then
        ngx.log(ngx.ERR, "No callback URL specified for route ", uri)
        return
    end

    if type == "callback" then
        local callback_credentials = get_header_value(callback_credentials_header)
        return request_callback(bakend_url, callback_url, callback_credentials, resp_body, content_type, status_code)
    else 
        return request_timeout(backend_url, timeout_ms, resp_body, content_type, status_code)
    end
end

local function get_header_value(headerName)
  return ngx.req.get_headers()[headerName]
end

--[[
透传请求，并设置超时时间（ms），如果超时，则直接返回设定的code和body
backend_url：上游服务地址
timeout_ms：超时毫秒数
resp_body： 超时返回的body内容
content_type: 超时返回的body的类型，默认：application/json; charset=utf-8
status_code：超时返回的http状态码，默认：200
]]
local function request_timeout(backend_url, timeout_ms, resp_body, content_type, status_code)
  content_type = content_type or "application/json; charset=utf-8"
  status_code = status_code or 200
  
  local httpc = http.new()
  httpc:set_timeout(timeout_ms)
  
  local req_method = ngx.req.get_method()
  local req_headers = ngx.req.get_headers()
  
  -- 修改请求头
  req_headers["Connection"] = nil
  req_headers["Host"] = ngx.var.host .. ':' .. ngx.var.server_port
  req_headers["X-Real-IP"] = ngx.var.remote_addr
  req_headers["X-Real-PORT"] = ngx.var.remote_port

  local x_forwarded_for = req_headers["X-Forwarded-For"]
  if x_forwarded_for then
      x_forwarded_for = x_forwarded_for .. ", " .. ngx.var.remote_addr
  else
      x_forwarded_for = ngx.var.remote_addr
  end
  req_headers["X-Forwarded-For"] = x_forwarded_for
  
  ngx.req.read_body()

  -- 构建后端请求 URL
  local pass_url = backend_url:gsub("/+$", "") .. ngx.var.uri
  if ngx.var.query_string then
      pass_url = pass_url .. "?" .. ngx.var.query_string
  end

  -- 向后端服务器发送请求
  local res, err = httpc:request_uri(pass_url, {
      method = req_method,
      headers = req_headers,
      body = ngx.req.get_body_data(),
      keepalive_timeout = 60,
      keepalive_pool = 10
  })

  -- 检查响应，如果失败则处理超时和其他错误
  if not res then
      if err == "timeout" then
          -- 超时情况返回自定义的响应
          ngx.status = status_code
          ngx.header["Content-Type"] = content_type
          ngx.say(resp_body)
          ngx.log(ngx.WARN, "Request to [", backend_url, "] timed out. Params: ", ngx.req.get_body_data())
          return ngx.exit(status_code)
      else
          -- 其他错误按原样返回错误信息
          ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
          ngx.header["Content-Type"] = "application/json; charset=utf-8"
          ngx.say(cjson.encode({ error = "Failed to connect to backend", detail = err }))
          ngx.log(ngx.ERR, "Request to [", backend_url, "] failed: ", err)
          return ngx.exit(ngx.status)
      end
  end

  -- 设置返回状态码
  ngx.status = res.status

  -- 移除特定响应头
  res.headers["Transfer-Encoding"] = nil
  res.headers["Connection"] = nil

  for k, v in pairs(res.headers) do
      ngx.header[k] = v
  end

  -- 返回响应体内容
  ngx.say(res.body)
  return ngx.exit(res.status)
end

-- 异步透传请求，并在完成后回调
local function async_request_and_callback(backend_url, request_uri, callback_url, callback_credentials, req_method, req_headers, req_body)
    local httpc = http.new()
    
    -- 向后端服务器发送请求
    local res, err = httpc:request_uri(backend_url, {
        method = req_method,
        headers = req_headers,
        body = req_body,
        keepalive_timeout = 60,
        keepalive_pool = 10
    })
    
    if not res then
        ngx.log(ngx.ERR, "Failed to request backend: ", err)
        return
    end

    -- 准备向回调 URL 发送请求的数据
    local callback_httpc = http.new()
    local callback_body = cjson.encode({
        request = request_uri,
        credentials = callback_credentials,
        status = res.status,
        headers = res.headers,
        body = res.body
    })

    -- 向 callback_url 发起请求，传递后端的响应内容
    local callback_res, callback_err = callback_httpc:request_uri(callback_url, {
        method = "POST",
        body = callback_body,
        headers = {
            ["Content-Type"] = "application/json; charset=utf-8",
            ["Content-Length"] = #callback_body
        }
    })

    if not callback_res then
        ngx.log(ngx.ERR, "Failed to send callback to ", callback_url, ": ", callback_err)
    else
        ngx.log(ngx.INFO, "Callback to ", callback_url, " succeeded with status ", callback_res.status)
    end
end

-- 主方法，处理客户端请求并异步透传至后端
local function request_callback(backend_url, callback_url, callback_credentials, resp_body, content_type, status_code)
    content_type = content_type or "application/json; charset=utf-8"
    status_code = status_code or 200

    -- 获取请求方法、头信息、请求体
    local req_method = ngx.req.get_method()
    local req_headers = ngx.req.get_headers()
    req_headers["Connection"] = nil
    req_headers["Host"] = ngx.var.host .. ':' .. ngx.var.server_port
    req_headers["X-Real-IP"] = ngx.var.remote_addr
    req_headers["X-Real-PORT"] = ngx.var.remote_port

    local x_forwarded_for = req_headers["X-Forwarded-For"]
    if x_forwarded_for then
        x_forwarded_for = x_forwarded_for .. ", " .. ngx.var.remote_addr
    else
        x_forwarded_for = ngx.var.remote_addr
    end
    req_headers["X-Forwarded-For"] = x_forwarded_for

    ngx.req.read_body()
    local req_body = ngx.req.get_body_data()

    -- 构建后端请求 URL
    local pass_url = backend_url:gsub("/+$", "") .. ngx.var.uri
    if ngx.var.query_string then
        pass_url = pass_url .. "?" .. ngx.var.query_string
    end

    -- 立即返回给客户端
    ngx.status = status_code
    ngx.header["Content-Type"] = content_type
    ngx.say(resp_body)
    ngx.flush()  -- 刷新输出缓冲区，将响应立即返回给客户端

    -- 异步调用透传请求，并在收到响应后回调
    local ok, err = ngx.timer.at(0, function()
        async_request_and_callback(pass_url, ngx.var.uri, callback_url, callback_credentials, req_method, req_headers, req_body)
    end)

    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer: ", err)
    end

    return ngx.exit(status_code)
end

return _M
