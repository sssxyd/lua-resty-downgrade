# 第三方服务降级/异步网关插件
在网关上配置toml路由规则文件，实现对第三方接口的超时服务降级和耗时接口的同步转异步功能

# 用法
## 安装网关和插件
```bash
yum install -y yum-utils

# For CentOS 8 or older
yum-config-manager --add-repo https://openresty.org/package/centos/openresty.repo
# For CentOS 9 or later
yum-config-manager --add-repo https://openresty.org/package/centos/openresty2.repo

yum install -y openresty
yum install -y openresty-opm openresty-resty

# lua-resty-downgrade call zlib by ffi
yum install zlib-devel

opm get sssxyd/lua-resty-downgrade

systemctl enable openresty
```

## 编写路由规则文件
`vim /path/to/your_router_rules.toml`
```toml
["/thirdpart/user/getPageData"]
# 当前路由的请求，适配超时服务降级模式
type = "timeout"
# 上游服务地址，支持https
backend_url = "http://127.0.0.1:8080"
# 超时时间，单位毫秒
timeout_ms = 250
# 超时服务降级触发后，返回的HTTP状态码，默认200
#status_code = 200
# 超时服务降级触发后，返回的ContentType，默认JSON
#content_type = "application/json; charset=utf-8"
# 超时服务降级触发后，返回的Body内容
resp_body = '''
{
    "code": 0,
    "msg": "success",
    "result": {
        "total": 1,
        "data": [
            {
                "id": 1,
                "name": "test",
                "description": "test",
                "status": 1,
                "createTime": 1600000000,
                "updateTime": 1600000000
            }
        ]
    }
}
'''

["/thirdpart/traffic/getTrafficNo"]
# 当前路由的请求，适配同步转异步模式
type = "callback"
# 上游服务地址，支持https
backend_url = "http://127.0.0.1:8080"
# 回调地址，向该接口 Post JSON格式的数据
callback_url = "http://192.168.1.1:18080/handle_callback"
# 当前请求中存储回调凭证的header名称，默认：X-Callback-Credentials，该header可以为空
#callback_credentials_header = "X-Callback-Credentials"
# 同步转异步触发后，立即返回的HTTP状态码，默认200
#status_code = 200
# 同步转异步触发后，立即返回的ContentType，默认JSON
#content_type = "application/json; charset=utf-8"
# 同步转异步触发后，立即返回的Body内容
resp_body = '''
{
    "code": 0,
    "msg": "success",
    "result": {
        "trafficno": "test"
    }
}
'''
```

## 配置Server Block
`vim /usr/local/openresty/nginx/conf/nginx.conf`
```conf

server {
    listen 8888;
    server_name _;
    root /usr/local/openresty/nginx/html;
    
    charset utf-8;
    index index.php index.html index.htm;

    access_log /var/log/nginx/access.downgrade.log  main;
    error_log /var/log/nginx/error.downgrade.log;

    autoindex off;

    # 静态文件和其他路径请求
    location / {
        try_files $uri $uri/ /index.html?$query_string;
        proxy_pass  http://127.0.0.1:8080; 
    }

    # 超时降级/同步转异步
    location /thirdpart/ {
        access_by_lua_block {
            local downgrade = require "resty.downgrade"
            downgrade.load_rules("/path/to/your_route_rules.toml")
            downgrade.proxy_pass(ngx.var.uri)
        }
        # 未适配的接口透传
        proxy_pass  http://127.0.0.1:8080; 
    }
}

```

## 回调函数的JSON数据格式
| 字段 | 类型 | 说明 |
| --- | --- | --- |
| request_time | float | 网关收到请求的unix时间戳 |
| request_uri | string | 请求path |
| request_params | object | 请求参数表，从Get请求的query字符串解析或从Post FormData/Json 请求的body解析|
| request_body | string | 请求体，如果 request_params 解析成功，则本字段的值设置为空字符串|
| callback_credentials | string | 回调凭证，调用方通过 http header 设置 |
| response_time | float | 网关收到上游服务反馈的unix时间戳 |
| response_status_code | int | 上游服务返回的HTTP状态码 |
| response_http_headers | object | 上游服务返回的HTTP Headers |
| response_body | string | 上游服务返回的http响应体 |

## 插件函数表
| 函数名称 | 是否必须 | 说明 |
| --- | --- | --- |
| load_rules(toml_path) | 是 | 从 toml_path 指定的路径加载路由配置文件，本方法有缓存，只加载一次 |
| proxy_pass(uri) | 是 | 根据uri从路由配置文件中找到对应的规则，并执行，如果找不到则直接返回 |
| set_http_timeout(timeout) | 否 | 设置网关创建的http请求的timeout时间（单位毫秒），默认60000毫秒|
| set_http_keepalive(timeout, pool_size) | 否 | 设置网关创建的http请求keepalive的timeout时间（单位毫秒）和连接池大小，默认60000毫秒，连接池最大15个连接|