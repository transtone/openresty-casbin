local jwt = require "resty.jwt"
ngx.header.content_type = "application/json;charset=utf8"
local header = ngx.req.get_headers()
local jwt_salt = '6c69ef4a-29df-41d2-a72c-ece1ccde1e16'
local jwt_obj = jwt:verify(jwt_salt, header.token)

local Enforcer = require("casbin")
local Adapter = require("casbin.mysql")
local mysql_conf = {
    timeout = 1200,
    connect_config = {
        host = "127.0.0.1",
        port = 3306,
        database = "casbin",
        user = "root",
        password = "openresty_casbin",
        max_packet_size = 1024 * 1024,
        charset = "utf8",
        ssl = false,
        ssl_required = nil,
        socket_type = "nginx", -- "luasocket"
        application_name = "iot"
    },
    -- 连接池，有此参数会做 keepalive 处理
    pool_config = {
        max_idle_timeout = 20000, -- 20s
        pool_size = 50 -- connection pool size
    }
}

local a = Adapter:new(mysql_conf, "auth_casbin_rule")
local e = Enforcer:new("/opt/openresty/nginx/conf/lua/casbin/rbac_model.conf", a)

local cjson = require "cjson"
local response = {}

-- 特殊路由:
if ngx.var.request_uri == '/api/auth/login' then
    -- 1. 用户登录、注册
    goto theEnd
end

if jwt_obj.verified == true then
    ngx.var.userId = jwt_obj.payload.userId
    ngx.var.companyCode = jwt_obj.payload.companyCode
end

if ngx.var.userId == '' then
    response['code'] = 401
    response['msg'] = "请登录!"
    ngx.say(cjson.encode(response))
    goto theEnd
end

local userId = ngx.var.userId -- 用户id
local path = ngx.var.request_uri -- 请求路径
local method = ngx.var.request_method -- 请求方法

if ngx.var.userId ~= '1' and not e:enforce(userId, path, method) then
    response['msg'] = "该用户没有接口访问权限!"
    response['code'] = 403
    ngx.say(cjson.encode(response))
    goto theEnd
end

-- api: 添加用户角色
if method == 'POST' and ngx.var.request_uri == '/api/casbin/addRoleForUser' then
    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if nil == body then
        response['msg'] = "参数为空!"
        response['code'] = 201
        ngx.say(cjson.encode(response))
        goto theEnd
    end

    local data = cjson.decode(body)

    if nil == data then
        response['msg'] = "参数错误!"
        response['code'] = 201
        ngx.say(cjson.encode(response))
    else
        local res, err = e:AddRoleForUser(data.user, data.role, data.dom)
        if nil ~= err then
            response['msg'] = "添加角色失败!"
            response['code'] = 201
            ngx.say(cjson.encode(response))
        else
            response['msg'] = "success"
            response['code'] = 0
            ngx.say(cjson.encode(response))
        end
    end
    goto theEnd
end
-- api: 删除用户角色
if method == 'DELETE' and ngx.var.request_uri == '/api/casbin/deleteRoleForUser' then
    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if nil == body then
        response['msg'] = "参数为空!"
        response['code'] = 201
        ngx.say(cjson.encode(response))
        goto theEnd
    end

    local data = cjson.decode(body)

    if nil == data then
        response['msg'] = "参数错误!"
        response['code'] = 201
        ngx.say(cjson.encode(response))
    else
        local result, err = e:DeleteRoleForUser(data.user, data.role, data.dom)
        if nil ~= err then
            response['msg'] = "删除角色失败!"
            response['code'] = 201
            ngx.say(cjson.encode(response))
        else
            response['msg'] = "success"
            response['code'] = 0
            ngx.say(cjson.encode(response))
        end
    end
    -- assert.is.Same({{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}}, e:GetPermissionsForUser("admin", "domain1"))
    -- assert.is.Same({{"alice", "domain1", "data2", "read"}, {"role:writer", "domain1", "data1", "write"}}, e:GetImplicitPermissionsForUser("alice", "domain1"))
    -- assert.is.Same({}, e:GetUsersForRoleInDomain("non_exist", "domain2"))
    -- assert.is.Same({{"admin", "domain1", "data1", "read"}, {"admin", "domain1", "data1", "write"}}, e:GetPermissionsForUserInDomain("admin", "domain1"))
    -- assert.is.Same({"alice", "admin"}, e:GetAllUsersByDomain("domain1"))
    -- e:AddPolicy("bob", "data1", "read")
    -- e:AddGroupingPolicy("alice", "admin")
    goto theEnd
end
-- api: 获取用户角色
if method == 'POST' and ngx.var.request_uri == '/api/casbin/getRolesForUser' then
    ngx.req.read_body()
    local body = ngx.req.get_body_data()

    if nil == body then
        response['msg'] = "参数为空!"
        response['code'] = 201
        ngx.say(cjson.encode(response))
        goto theEnd
    end

    local data = cjson.decode(body)

    if nil == data then
        response['msg'] = "参数错误!"
        response['code'] = 201
        ngx.say(cjson.encode(response))
    else
        -- assert.is.Same({"admin", "admin1", "admin2"}, e:GetRolesForUser("bob", "domain1")) -- 获取直接角色
        -- assert.is.Same({"role:global_admin", "role:reader", "role:writer"}, e:GetImplicitRolesForUser("alice", "domain1")) -- 获取所有角色(包括隐含的继承角色)
        local result, err = e:GetRolesForUser(data.user, data.dom)
        if nil ~= err then
            response['msg'] = "获取角色失败!"
            response['code'] = 201
            ngx.say(cjson.encode(response))
        else
            response['msg'] = "success"
            response['code'] = 0
            response['result'] = result
            ngx.say(cjson.encode(response))
        end
    end
    goto theEnd
end

::theEnd::
