local _M = {
  _VERSION = '0.3.2',
  _Default_Http_Timeout = 60000,
  _Default_Http_Keepalive = 60000,
  _Default_Http_Pool_Size = 1024,
}

local http = require("resty.http")
local cjson = require("cjson")
local ffi = require("ffi")
local _Domain_Routes = {}
local _Domain_Versions = {}
local _Http_Timeout = nil
local _Http_Keepalive = nil
local _Http_Pool_Size = nil

---@class z_stream: ffi.cdata*
---@field next_in ffi.cdata*       -- 输入缓冲指针
---@field avail_in integer         -- 输入缓冲区大小
---@field total_in integer         -- 总共读取字节数
---@field next_out ffi.cdata*      -- 输出缓冲指针
---@field avail_out integer        -- 输出缓冲区大小
---@field total_out integer        -- 总共写入字节数
---@field msg string               -- 错误消息
---@field state ffi.cdata*         -- 内部状态
---@field zalloc ffi.cdata*        -- 内存分配函数
---@field zfree ffi.cdata*         -- 内存释放函数
---@field opaque ffi.cdata*        -- 内存上下文指针
---@field data_type integer        -- 数据类型
---@field adler integer            -- Adler-32 校验
---@field reserved integer         -- 保留字段
ffi.cdef[[
typedef struct {
    const unsigned char *next_in;
    unsigned int avail_in;
    unsigned long total_in;
    unsigned char *next_out;
    unsigned int avail_out;
    unsigned long total_out;
    const char *msg;
    void *state;
    void *zalloc;
    void *zfree;
    void *opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
} z_stream;

int inflateInit2_(z_stream *strm, int windowBits, const char *version, int stream_size);
int inflate(z_stream *strm, int flush);
int inflateEnd(z_stream *strm);
]]

local zlib = ffi.load("z")

---@return z_stream
local function _create_zstream()
	---@type any
	return ffi.new("z_stream")
end

local function _decompress_gzip(data)
    local buffer_size = 16384 -- 16KB buffer size
    ---@type z_stream
	local zstream = _create_zstream()
    ---@type ffi.cdata*
    local out_buffer = ffi.new("unsigned char[?]", buffer_size)

    zstream.next_in = data
    zstream.avail_in = #data
    zstream.next_out = out_buffer
    zstream.avail_out = buffer_size

    local Z_OK = 0
    local Z_STREAM_END = 1
    local Z_FINISH = 4

    local windowBits = 15 + 32 -- gzip and deflate decoding
	local ret = zlib.inflateInit2_(zstream, windowBits, "1.2.11", ffi.sizeof("z_stream"))

    if ret ~= Z_OK then
        error("Failed to initialize zlib stream")
    end

    local output = {}
    while true do
        ret = zlib.inflate(zstream, Z_FINISH)
        if ret == Z_STREAM_END then break end
        if ret ~= Z_OK and ret ~= Z_STREAM_END then
            zlib.inflateEnd(zstream)
            error("Zlib inflate failed with error code: " .. ret)
        end

        -- Append decompressed data to output
        table.insert(output, ffi.string(out_buffer, buffer_size - zstream.avail_out))
        zstream.next_out = out_buffer
        zstream.avail_out = buffer_size
    end

    zlib.inflateEnd(zstream)
    table.insert(output, ffi.string(out_buffer, buffer_size - zstream.avail_out))
    return table.concat(output)
end


local function _parse_toml(toml, options)
	options = options or {}
	local strict = (options.strict ~= nil and options.strict or false)

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
		local digits = tonumber(num)

		if not float then
			return {
				-- lua will automatically convert the result
				-- of a power operation to a float, so we have
				-- to convert it back to an int with math.floor
				value = math.floor(digits * 10^exp),
				type = "int",
			}
		end

		return {value = digits * 10^exp, type = "float"}
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
				buffer = tostring(tonumber(buffer))
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

local function _parse_url(url)
    local parsed = {}
    -- 修正正则表达式，支持更通用的URL解析
    parsed.scheme, parsed.host, parsed.port, parsed.path, parsed.query, parsed.fragment =
        url:match("^(https?)://([^:/?#]+):?(%d*)([^?#]*)%??([^#]*)#?(.*)")

    -- 默认路径为 "/"
    if not parsed.path or parsed.path == "" then
        parsed.path = "/"
    end

    -- 默认端口号
    parsed.port = tonumber(parsed.port) or (parsed.scheme == "https" and 443 or 80)

    return parsed
end

local function _is_valid_http_url(url)
    -- 定义简单的 HTTP/HTTPS URL 正则表达式
    local pattern = "^https?://[%w-_%.%?%.:/%+=&]+$"

    -- 使用 string.match 检查 URL 是否匹配
    return url:match(pattern) ~= nil
end

local function _proxy_request_headers()
    local req_headers = ngx.req.get_headers()
    req_headers["Connection"] = "Keep-Alive"
    req_headers["X-Real-IP"] = ngx.var.remote_addr
    req_headers["X-Real-PORT"] = ngx.var.remote_port

    local x_forwarded_for = req_headers["X-Forwarded-For"]
    if x_forwarded_for then
        x_forwarded_for = x_forwarded_for .. ", " .. ngx.var.remote_addr
    else
        x_forwarded_for = ngx.var.remote_addr
    end
    req_headers["X-Forwarded-For"] = x_forwarded_for
    return req_headers
end

local function _read_request_body()
    -- 检查是否已有缓存数据
    if ngx.ctx.request_body_cache then
        return ngx.ctx.request_body_cache
    end

    -- 确保请求体已被读取
    ngx.req.read_body()

    -- 获取 body 数据
    local body_data = ngx.req.get_body_data()
    if body_data then
        return body_data
    end

    -- 如果 body 数据过大，可能被写入临时文件
    local body_file = ngx.req.get_body_file()
    if body_file then
        local file, err = io.open(body_file, "r")
        if not file then
            ngx.log(ngx.ERR, "Failed to open body file: ", err)
            return nil, "Failed to read body file"
        end

        local body = file:read("*a")
        file:close()

        -- 缓存数据到 ngx.ctx
        ngx.ctx.request_body_cache = body
        return body
    end

    -- 如果既没有 body 数据，也没有临时文件，返回空值
    ngx.ctx.request_body_cache = ""
    return ""
end

local function _decompress_resp_body(content_encoding, resp_body)
	if content_encoding == "gzip" or content_encoding == "deflate" then
		return _decompress_gzip(resp_body)
	end
	return resp_body
end

local function _read_response_body(res, timeout_ms)
    local body_reader = res.body_reader
    local max_chunk_size = 8192 -- 每次读取的块大小，默认 8KB
    local chunks = {}
	local start_time = ngx.now()

	local resp_body = ""
    if body_reader then
        -- 使用流式读取逐块读取响应体
		repeat
			local elapsed_time = (ngx.now() - start_time) * 1000
			if timeout_ms > 0 and elapsed_time > timeout_ms then
				return "", "timeout"
			end
		
			local chunk, read_err = body_reader(max_chunk_size)
			if read_err then
				ngx.log(ngx.ERR, "Error reading chunk: ", read_err)
				return "", read_err
			end
		
			if chunk then
				table.insert(chunks, chunk)
			end
		until not chunk

        -- 合并所有块为完整的响应体
        resp_body = table.concat(chunks)
    elseif res.body then
        -- 如果流式读取不可用，直接读取响应体
        resp_body = res.body or ""
    else
        -- 如果没有响应体可用，返回空字符串
        resp_body = ""
    end

	if resp_body == "" then
		return "", nil
	end

	return resp_body, nil
end

local function _async_http_request(url, method, headers, body, timeout_ms)
    -- ngx.log(ngx.INFO, "[ASYNC REQUEST] URL: ", url, ", Method: ", method, ", Headers: ", cjson.encode(headers))

    local httpc = http.new()
	if not httpc then
		return nil, "Failed to create http client"
	end
    httpc:set_timeout(timeout_ms > 0 and timeout_ms or _M.get_http_timeout())

    local parsed_url = _parse_url(url)
    local scheme, host, port, path, query, fragment = parsed_url.scheme, parsed_url.host, parsed_url.port, parsed_url.path, parsed_url.query, parsed_url.fragment

    -- Connect
    local ok, err = httpc:connect(host, port)
    if not ok then
        return nil, "Failed to connect: " .. err
    end

	-- 如果请求头中包含 Accept-Encoding，则修正为 gzip, deflate，因为本程序只能解析这两种压缩格式
	if headers["Accept-Encoding"] ~= nil then
		headers["Accept-Encoding"] = nil
		headers["Accept-Encoding"] = "gzip, deflate"
	end

    -- SSL handshake
    if scheme == "https" then
        local session, ssl_err = httpc:ssl_handshake(nil, host, false)
        if not session then
            return nil, "SSL handshake failed: " .. ssl_err
        end
    end

    -- Make request
    local res, req_err = httpc:request({
        path = path,
        method = method or "GET",
		query = query,
		fragment = fragment,
        headers = headers,
        body = body,
    })

    if not res then
        httpc:close()
        return nil, req_err
    end

    -- Read response body
    local resp_body, read_err = _read_response_body(res, timeout_ms)
	if read_err then
		httpc:close()
		return nil, read_err
	end

	local do_keep_alive = _M.get_keepalive_timeout() > 0 and _M.get_keepalive_pool() > 0
	if do_keep_alive then
		local keepalive_ok, keepalive_err = httpc:set_keepalive(_M.get_keepalive_timeout(), _M.get_keepalive_pool())
		if not keepalive_ok then
			ngx.log(ngx.ERR, "Failed to set keepalive: ", keepalive_err)
		end
	else
		httpc:close()
	end

	-- 将 res.headers 转换为普通的 Lua 表
	local resp_headers = {}
	for k, v in pairs(res.headers) do
		resp_headers[string.lower(k)] = v
	end

    -- Return response
    return {
        status = res.status,
        headers = resp_headers,
        body = resp_body,
    }, nil
end

local function _parse_request_params(req_method, body_data)
    if req_method == "GET" then
        return ngx.req.get_uri_args()
    elseif req_method == "POST" then
        local content_type = ngx.var.content_type or ""
		content_type = string.lower(content_type)
        if content_type:find("application/json") and body_data then
            local ok, json_params = pcall(cjson.decode, body_data)
            if ok then
                return json_params
            else
                ngx.log(ngx.ERR, "Failed to decode JSON: ", json_params)
                return nil
            end
        elseif content_type:find("application/x%-www%-form%-urlencoded") then
            return ngx.req.get_post_args()
        end
    end
    return nil
end

local function _is_nil_or_empty(value)
    -- 检查是否为 nil
    if value == nil then
        return true
    end

	-- 检查是否为空字符串
	if type(value) == "string" and value == "" then
		return true
	end

    -- 检查是否为数字 0
    if type(value) == "number" and value == 0 then
        return true
    end	

    -- 检查是否为空表或空数组
    if type(value) == "table" then
        -- `next` 返回 nil 表示表是空的（无键值对）
        if next(value) == nil then
            return true
        end

        -- 如果是数组，检查数组长度是否为 0
        local is_array = true
        for k, _ in pairs(value) do
            if type(k) ~= "number" then
                is_array = false
                break
            end
        end

        if is_array and #value == 0 then
            return true
        end
    end

    return false
end

local function _trim_route_name(route_name)
	if route_name:sub(1, 1) == "/" then
		route_name = route_name:sub(2)
	end
	if route_name:sub(-1) == "/" then
		route_name = route_name:sub(1, -2)
	end
	return route_name:gsub("^%s*(.-)%s*$", "%1")
end

local function _remove_trailing_slash(str)
    if str:sub(-1) == "/" then
        return str:sub(1, -2)
    end
    return str
end

local function _string_split(str, delimiter)
    local result = {}
    local pattern = string.format("([^%s]+)", delimiter)  -- 匹配非 delimiter 的字符
    for part in string.gmatch(str, pattern) do
        table.insert(result, part)
    end
    return result
end

-- 判断一个字符串是否是另一个字符串的前缀
local function _is_prefix(prefix, str)
    return str:sub(1, #prefix) == prefix
end

-- 查找输入 name 中，所有能作为前缀的 key，返回最长的前缀
local function _find_longest_prefix(name, routes)
	if not name or name == "" then
		return nil
	end
	if not routes or type(routes) ~= "table" then
		return nil
	end

    local longest_prefix = ""
    
    for key, _ in pairs(routes) do
        if _is_prefix(key, name) and #key > #longest_prefix then
            longest_prefix = key
        end
    end

    return longest_prefix
end

local function _get_route_rules(name_space)
	if not name_space or name_space == "" then
		return {}
	end

	-- 没有读取过路由规则配置文件
	local toml_read_version = ngx.shared.downgrade:get(name_space .. ":version")
	if not toml_read_version then
		return {}
	end

	-- 配置文件没有重新读取，直接返回缓存的路由规则
	if _Domain_Versions[name_space] ~= nil and _Domain_Versions[name_space] == toml_read_version then
		return _Domain_Routes[name_space] or {}
	end

	-- 重新从共享内存中恢复路由规则缓存
	local route_names_str = ngx.shared.downgrade:get(name_space .. ":routes")
	if not route_names_str or route_names_str == "" then
		_Domain_Routes[name_space] = {}
	else
		local route_names = _string_split(route_names_str, "|")
		local rules = {}
		for _, route_name in ipairs(route_names) do
			local rule_str = ngx.shared.downgrade:get(name_space .. ":" .. route_name)
			if rule_str then
				rules[route_name] = cjson.decode(rule_str)
			end
		end
		_Domain_Routes[name_space] = rules
	end

	-- 更新缓存更新时间
	_Domain_Versions[name_space] = toml_read_version
	
	return _Domain_Routes[name_space] or {}
end


function _M.set_http_timeout(timeout)
    if type(timeout) == "number" and timeout > 0 then
        _Http_Timeout = timeout
		ngx.shared.downgrade:set("http_timeout", timeout)
    end
end

function _M.get_http_timeout()
	if _Http_Timeout == nil then
		_Http_Timeout = ngx.shared.downgrade:get("http_timeout") or _M._Default_Http_Timeout
	end
	return _Http_Timeout
end

function _M.set_keepalive_timeout(timeout)
	if type(timeout) == "number" and timeout >= 0 then
		_Http_Keepalive = timeout
		ngx.shared.downgrade:set("http_keepalive", timeout)
	end
end

function _M.get_keepalive_timeout()
	if _Http_Keepalive == nil then
		_Http_Keepalive = ngx.shared.downgrade:get("http_keepalive") or _M._Default_Http_Keepalive
	end
	return _Http_Keepalive
end

function _M.set_keepalive_pool(pool_size)
    if type(pool_size) == "number" and pool_size >= 0 then
		_Http_Pool_Size = pool_size
		ngx.shared.downgrade:set("http_pool_size", pool_size)
	end
end

function _M.get_keepalive_pool()
	if _Http_Pool_Size == nil then
		_Http_Pool_Size = ngx.shared.downgrade:get("http_pool_size") or _M._Default_Http_Pool_Size
	end
	return _Http_Pool_Size
end

-- 从指定路径加载路由规则，并缓存在全局变量
function _M.load_rules(toml_path, name_space)

    local config_file = io.open(toml_path, "r")
    if not config_file then
        ngx.log(ngx.ERR, "Failed to open config file " .. toml_path)
        return
    end

    local config_content = config_file:read("*a")
    config_file:close()

	-- ngx.log(ngx.INFO, "rules: ", config_content)
	local rules = _parse_toml(config_content)
	local route_names = {}
	for api, rule in pairs(rules) do
		-- 将路由规则缓存到共享内存中
		local route_name = _trim_route_name(api)
		table.insert(route_names, route_name)
		ngx.shared.downgrade:set(name_space .. ":" .. route_name, cjson.encode(rule))
	end
	local route_name_str = table.concat(route_names, "|")
	ngx.log(ngx.ERR, ">>>Load [", name_space, "] Rules [", route_name_str, "]")
	local pre_namespace_routes = ngx.shared.downgrade:get(name_space .. ":routes")
	if pre_namespace_routes then
		route_name_str = pre_namespace_routes .. "|" .. route_name_str
	end
	ngx.shared.downgrade:set(name_space .. ":routes", route_name_str) 
	ngx.shared.downgrade:set(name_space .. ":version", os.time())
end

-- 超时降级处理
local function request_timeout(route_name, backend_url, timeout_ms, resp_body, content_type, status_code)
    content_type = content_type or "application/json; charset=utf-8"
    status_code = status_code or 200

    local req_uri = ngx.var.uri
    local req_method = ngx.req.get_method()
    local req_headers = _proxy_request_headers()
    local req_body = _read_request_body()

    -- 构建后端请求 URL
    local pass_url = _remove_trailing_slash(backend_url) .. req_uri
    if ngx.var.query_string then
        pass_url = pass_url .. "?" .. ngx.var.query_string
    end

    ngx.log(ngx.INFO, "pass ", route_name, " request: ", req_uri, " to pass_url: ", pass_url, " for timeout: ", timeout_ms, "ms")

    -- 向后端服务器发送请求
    local res, err = _async_http_request(pass_url, req_method, req_headers, req_body, timeout_ms)

    if not res then
        if err == "timeout" then
            -- 超时情况返回自定义的响应
            ngx.status = status_code
            ngx.header["Content-Type"] = content_type
            ngx.say(resp_body)
            ngx.log(ngx.ERR, "[TIMEOUT_YES] ", "route: ", route_name, ", pass_url: ", pass_url, ", timeout: ", timeout_ms)
            return ngx.exit(status_code)
        else
            -- 其他错误按原样返回错误信息
            ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
            ngx.header["Content-Type"] = "application/json; charset=utf-8"
            ngx.say(cjson.encode({ error = "Failed to connect to backend", detail = err }))
            ngx.log(ngx.ERR, "[TIMEOUT_ERR] route: ", route_name, " Request to [", backend_url, "] failed: ", err)
            return ngx.exit(ngx.status)
        end
    else
        -- 返回后端服务器的响应
        ngx.status = res.status
        for k, v in pairs(res.headers) do
            ngx.header[k] = v
        end
        ngx.say(res.body)
        return ngx.exit(res.status)
    end
end

-- 异步透传请求，并在完成后回调
local function async_request_and_callback(route_name, backend_url, request_time, request_uri, request_params, callback_url, callback_credentials, req_method, req_headers, req_body)
    ngx.log(ngx.INFO, "pass callback request ", request_uri, " to ", backend_url)

    -- 向后端服务器发送请求
    local res, err = _async_http_request(backend_url, req_method, req_headers, req_body, _M.get_http_timeout())
    if not res then
        ngx.log(ngx.ERR, "route: ", route_name, " async http reuest to ", backend_url, " failed: ", err)
        res = {
            status = ngx.HTTP_BAD_GATEWAY,
            headers = {
                ["Content-Type"] = "text/plain; charset=utf-8"
            },
            body = err
        }
    end

    local res_body = _decompress_resp_body(res.headers["content-encoding"], res.body)

    -- 准备向回调 URL 发送请求的数据
	local resp_data = {
        request_time = request_time,
        request_uri = request_uri,
        request_params = request_params or {},
        request_body = _is_nil_or_empty(request_params) and req_body or "",
        callback_credentials = callback_credentials or "",
        response_time = ngx.now(),
        response_status_code = res.status,
        response_http_headers = res.headers,
        response_body = res_body
    }
    local ok, callback_body = pcall(cjson.encode, resp_data)
    if not ok then
        ngx.log(ngx.ERR, "Failed to encode callback body: ", resp_data)
        return
    end

	if _is_nil_or_empty(callback_url) or not _is_valid_http_url(callback_url) then
		ngx.log(ngx.ERR, "[CALLBACK_NO] route: ", route_name , " req_uri: ", request_uri, ", no callback, response: ", callback_body, ", status: ", res.status)
		return
	end

    -- 向 callback_url 发起请求，传递后端的响应内容
    res, err = _async_http_request(callback_url, "POST", {
        ["Content-Type"] = "application/json; charset=utf-8",
        ["Content-Length"] = #callback_body
    }, callback_body, _M.get_http_timeout())

    if not res then
        ngx.log(ngx.ERR, "[CALLBACK_ERR] route: ", route_name , " req_uri: ", request_uri, ", callback: ", callback_url, ", error: ", err)
    else
        ngx.log(ngx.ERR, "[CALLBACK_YES] route: ", route_name, " req_uri: ", request_uri, ", callback: ", callback_url, ", status: ", res.status)
    end
end

-- 同步变异步
local function request_callback(route_name, req_time, backend_url, callback_url, callback_credentials, resp_body, content_type, status_code)
    -- 获取请求方法、头信息、请求体
    local req_uri = ngx.var.uri
    local req_method = ngx.req.get_method()
    local req_headers = _proxy_request_headers()

    ngx.req.read_body()
    local req_body = ngx.req.get_body_data()

    local req_params = _parse_request_params(req_method, req_body)

    -- 构建后端请求 URL
    local pass_url = _remove_trailing_slash(backend_url) .. req_uri
    if ngx.var.query_string then
        pass_url = pass_url .. "?" .. ngx.var.query_string
    end

    -- 立即返回给客户端
    ngx.status = status_code
    ngx.header["Content-Type"] = content_type
    ngx.say(resp_body)
    ngx.flush()  -- 刷新输出缓冲区，将响应立即返回给客户端

    -- 异步调用透传请求，并在收到响应后回调
    local ok, err = ngx.timer.at(0, function(premature, ...)
        if premature then
            ngx.log(ngx.ERR, "Timer prematurely expired")
            return
        end

        local status, err = pcall(async_request_and_callback, ...)
        if not status then
            ngx.log(ngx.ERR, "Async callback failed: ", err)
        end
    end, route_name, pass_url, req_time, req_uri, req_params, callback_url, callback_credentials, req_method, req_headers, req_body)
    
    if not ok then
        ngx.log(ngx.ERR, "Failed to create timer: ", err)
    end

    return ngx.exit(status_code)
end

---根据传入的路由规则名称，执行该路由规则定义的操作
---@param route_name string 路由规则名称
---@param name_space string 共享内存命名空间
---@return nil	如果没有执行任何操作，则继续执行后续的请求处理，否则结束请求处理
function _M.proxy_pass(route_name, name_space)
	if route_name == nil or route_name == "" or name_space == nil or name_space == "" then
		return
	end
	route_name = _trim_route_name(route_name)
	local routes = _get_route_rules(name_space)
	local route = routes[route_name]
    if not route then
        return
    end

    local req_time = ngx.now()
	local backend_url = route["backend_url"]
	if _is_nil_or_empty(backend_url) or not _is_valid_http_url(backend_url) then
		ngx.log(ngx.ERR, "[PROXYPASS] backend_url: [", backend_url, "] is empty or invalid")
		return
	end

    local type = route["type"] or "timeout"
	local callback_url_header = route["callback_url_header"] or "X-Callback-URL"
    local callback_credentials_header = route["callback_credentials_header"] or "X-Callback-Credentials"
    local config_callback_url = route["callback_url"] or ""
	local timeout_ms_header = route["timeout_ms_header"] or "X-Timeout-MS"
    local resp_body = route["resp_body"] or "{}"
    local content_type = route["content_type"] or "application/json; charset=utf-8"
    local status_code = route["status_code"] or 200

	local req_headers = ngx.req.get_headers()

    if type == "callback" then
		local callback_url = req_headers[callback_url_header]
		if _is_nil_or_empty(callback_url) then
			callback_url = config_callback_url
		end

        local callback_credentials = req_headers[callback_credentials_header]
        return request_callback(route_name, req_time, backend_url, callback_url, callback_credentials, resp_body, content_type, status_code)
    else
		local timeout_ms = tonumber(req_headers[timeout_ms_header]) or tonumber(route["timeout_ms"]) or 500
        return request_timeout(route_name, backend_url, timeout_ms, resp_body, content_type, status_code)
    end
end

---解析请求参数
function _M.request_params()
	local req_method = ngx.req.get_method()
	local req_body = _read_request_body()
	local req_params = _parse_request_params(req_method, req_body)
	return req_params
end

---以 like 'routeName%' 的方式匹配路由规则
---@param uri string 请求路径
---@param name_space string 适用的规则的名称空间
---@return string|nil 路由规则名称
function _M.request_route(uri, name_space)
	if uri == nil or uri == "" then
		return nil
	end
	if #uri > 1024 then
		uri = uri:sub(1, 1024)
	end
	local query = _trim_route_name(uri)
	local routes = _get_route_rules(name_space)
	return _find_longest_prefix(query, routes)
end

return _M
