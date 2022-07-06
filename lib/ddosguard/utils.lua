-- Copyright (C) Anton Khalikov (antony66), NetAngels.RU

utils = {}

function utils.send_nocache_headers()
    ngx.header['Content-Type'] = "text/html; charset=utf-8"
    ngx.header['Expires'] = "Mon, 26 Jul 1980 00:00:00 GMT"
    ngx.header['Pragma'] = "no-cache"
    ngx.header['Cache-Control'] = "no-cache, no-store, must-revalidate"
    ngx.status = ngx.HTTP_SERVICE_UNAVAILABLE
end

function utils.send_cookie(control_cookie, rnd, cookie_domain)
    ngx.header['Set-Cookie'] = str_fmt('%s=%s_%s; max-age=%d; path=/; domain=%s; HttpOnly',
        USER_COOKIE_NAME, escape_uri(control_cookie), rnd, USER_COOKIE_TTL, cookie_domain
    )
end

return utils
