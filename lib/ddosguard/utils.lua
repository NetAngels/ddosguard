-- Copyright (C) Anton Khalikov (antony66), NetAngels.RU

local str_fmt = string.format
local header = ngx.header
local escape_uri = ngx.escape_uri
local status = ngx.status

utils = {}

function utils.send_nocache_headers()
    header['Content-Type'] = "text/html; charset=utf-8"
    header['Expires'] = "Mon, 26 Jul 1980 00:00:00 GMT"
    header['Pragma'] = "no-cache"
    header['Cache-Control'] = "no-cache, no-store, must-revalidate"
    status = ngx.HTTP_SERVICE_UNAVAILABLE
end

function utils.send_cookie(control_cookie, rnd, cookie_domain)
    header['Set-Cookie'] = str_fmt('%s=%s_%s; max-age=%d; path=/; domain=%s; HttpOnly',
        USER_COOKIE_NAME, escape_uri(control_cookie), rnd, USER_COOKIE_TTL, cookie_domain
    )
end

return utils
