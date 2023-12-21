local jwt = require "resty.jwt"
local header = ngx.req.get_headers()

local jwt_salt = '6c69ef4a-29df-41d2-a72c-ece1ccde1e16'

local jwt_obj = jwt:verify(jwt_salt, header.token)

if jwt_obj.verified == true then
    ngx.var.userId = jwt_obj.payload.userId
    ngx.var.companyCode = jwt_obj.payload.companyCode
end
