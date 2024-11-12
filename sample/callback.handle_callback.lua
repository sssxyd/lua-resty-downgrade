local cjson = require "cjson"

-- 读取请求体
ngx.req.read_body()
local body_data = ngx.req.get_body_data()

if not body_data then
    ngx.status = 400
    ngx.say("No body received")
    ngx.exit(ngx.HTTP_BAD_REQUEST)
end

-- 将解析后的对象写入 Nginx 日志
local encoded = ngx.encode_base64(body_data)
ngx.log(ngx.ERR, "CALLBACK_JSON[", encoded, "]")

-- 返回成功响应
ngx.status = 200
ngx.say("JSON received and logged successfully")
ngx.exit(ngx.HTTP_OK)
