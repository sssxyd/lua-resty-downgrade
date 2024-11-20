local cjson = require "cjson"

-- 日志文件路径
local log_file_path = "/var/log/nginx/error.callback.log"

-- 打开日志文件
local file, err = io.open(log_file_path, "r")
if not file then
    ngx.status = 500
    ngx.say("Failed to open log file: ", err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
end

-- 读取所有日志内容
local lines = {}
local file_lines = file and file:lines() or {}
for line in file_lines do
    -- 提取 Base64 内容 xxxx
    local base64_content = line:match("CALLBACK_JSON%[([^%]]+)%]")
    
    if not base64_content then
        goto continue
    end

    -- 解码 Base64 内容
    local decoded = ngx.decode_base64(base64_content)
    if not decoded then
        goto continue
    end

    local ok, log_entry = pcall(cjson.decode, decoded)
    if ok then
        local columns = {}
        for k, v in pairs(log_entry) do
            if type(v) == "table" then
                columns[k] = cjson.encode(v)
            else
                columns[k] = v
            end
        end
        table.insert(lines, columns)
    end

    ::continue:: -- 标记位置
end
file:close()

-- 实现 table.reverse 函数
local function table_reverse(tbl)
    local reversed = {}
    for i = #tbl, 1, -1 do
        table.insert(reversed, tbl[i])
    end
    return reversed
end

-- 倒序排列日志
lines = table_reverse(lines)

-- 生成 HTML 表格
local html = [[
<!DOCTYPE html>
<html>
<head>
    <title>Callback Response</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 8px;
            text-align: left;
        }
    </style>
</head>
<body>
    <h1>Callback Response</h1>
    <table>
        <tr>
]]

-- 生成表格内容
for _, entry in ipairs(lines) do
    html = html .. "<tr><th colspan='2'>回调数据</th></tr>\n"
    for key, value in pairs(entry) do
        html = html .. "<tr>" .. "<td>" .. tostring(key) .. "</td>"
        html = html .. "<td>" .. tostring(value) .. "</td>" .. "</tr>\n"
    end
    html = html .. "<tr><td colspan='2'></td></tr>\n"
end

html = html .. [[
    </table>
</body>
</html>
]]

-- 返回 HTML
ngx.header.content_type = "text/html; charset=utf-8"
ngx.say(html)
