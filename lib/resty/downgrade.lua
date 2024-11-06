local _M = {
  _VERSION = '0.1.1'
}

local http = require("resty.http")

--[[
透传请求，并设置超时时间（ms），如果超时，则直接返回设定的code和body
backend_url：上游服务地址
timeout_ms：超时毫秒数
resp_body： 超时返回的body内容
content_type: 超时返回的body的类型，默认：application/json; charset=utf-8
status_code：超时返回的http状态码，默认：200
]]
function _M.proxy_pass(backend_url, timeout_ms, resp_body, content_type, status_code)
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
          ngx.log(ngx.WARN, "Request to [", backend_url, "] timed out. Params: ", ngx.req.get_body_data() or "No body")
          return ngx.exit(status_code)
      else
          -- 其他错误按原样返回错误信息
          ngx.status = ngx.HTTP_INTERNAL_SERVER_ERROR
          ngx.header["Content-Type"] = "application/json; charset=utf-8"
          ngx.say(require("cjson").encode({ error = "Failed to connect to backend", detail = err }))
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

return _M
