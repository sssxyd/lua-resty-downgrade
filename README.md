# Third-Party Service Degradation/Asynchronous Gateway Plugin
Configure TOML routing rules on the gateway to implement timeout service degradation for third-party APIs and convert synchronous time-consuming interfaces to asynchronous ones.

# Usage
## Install Gateway and Plugin
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

## Edit Routing Rule File
`vim /path/to/your_router_rules.toml`
```toml
["/thirdpart/user/getPageData"]
# Requests for this route adapt to the timeout service degradation mode
type = "timeout"
# Upstream service address, supports https
backend_url = "http://127.0.0.1:8080"
# Timeout duration in milliseconds
timeout_ms = 250
# HTTP status code returned after timeout service degradation is triggered (default is 200)
#status_code = 200
# Content-Type returned after timeout service degradation is triggered (default is JSON)
#content_type = "application/json; charset=utf-8"
# Body content returned after timeout service degradation is triggered
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
# Requests for this route adapt to the synchronous-to-asynchronous mode
type = "callback"
# Upstream service address, supports https
backend_url = "http://127.0.0.1:8080"
# Callback address, posts JSON formatted data to this API
callback_url = "http://192.168.1.1:18080/handle_callback"
# Name of the HTTP header containing the callback credentials, defaults to "X-Callback-Credentials". This header can be empty.
#callback_credentials_header = "X-Callback-Credentials"
# HTTP status code returned immediately after triggering synchronous-to-asynchronous mode (default is 200)
#status_code = 200
# Content-Type returned immediately after triggering synchronous-to-asynchronous mode (default is JSON)
#content_type = "application/json; charset=utf-8"
# Body content returned immediately after triggering synchronous-to-asynchronous mode
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

## Configure the Server Block
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

    # Static files and other path requests
    location / {
        try_files $uri $uri/ /index.html?$query_string;
        proxy_pass  http://127.0.0.1:8080; 
    }

    # Timeout degradation / synchronous-to-asynchronous
    location /thirdpart/ {
        access_by_lua_block {
            local downgrade = require "resty.downgrade"
            downgrade.load_rules("/path/to/your_route_rules.toml")
            downgrade.proxy_pass(ngx.var.uri)
        }
        # Pass through for unsupported interfaces
        proxy_pass  http://127.0.0.1:8080; 
    }
}

```

## JSON Data Format for Callback Function
| Field | Type | Description |
| --- | --- | --- |
| request_time | float | The UNIX timestamp when the gateway receives the request |
| request_uri | string | The request path |
| request_params | object | Parameters of the request, parsed from the GET query string or POST FormData/JSON body |
| request_body | string | The request body. If request_params is successfully parsed, this field will be an empty string |
| callback_credentials | string | Callback credentials set via HTTP headers by the client |
| response_time | float | The UNIX timestamp when the gateway receives feedback from the upstream service |
| response_status_code | int | HTTP status code returned by the upstream service |
| response_http_headers | object | HTTP headers returned by the upstream service |
| response_body | string | HTTP response body returned by the upstream service |

## Plugin Function Table
| Function Name	 | Required | Description |
| --- | --- | --- |
| load_rules(toml_path) | Yes | Loads routing configuration from the specified toml_path. This method uses caching and will only load once. |
| proxy_pass(uri) | Yes | Finds the corresponding rule for the URI from the routing configuration and executes it. If no rule is found, the request passes through directly. |
| set_http_timeout(timeout) | No | Sets the timeout duration (in milliseconds) for HTTP requests created by the gateway. Default is 60,000 milliseconds. |
| set_http_keepalive(timeout, pool_size) | No | Sets the keepalive timeout duration (in milliseconds) and connection pool size for HTTP requests created by the gateway. Defaults are 60,000 milliseconds and a maximum of 15 connections. |