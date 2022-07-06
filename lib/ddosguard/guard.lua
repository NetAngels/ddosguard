-- Copyright (C) Anton Khalikov (antony66), NetAngels.RU

local guard = {}

local redis = require "resty.redis"
local protectors = require "ddosguard.protectors"
local recaptcha = require "ddosguard.recaptcha"
local resolver = require "resty.dns.resolver"
local http = require "resty.http"

local cache = ngx.shared.cache
local encode_base64 = ngx.encode_base64
local sha1_bin = ngx.sha1_bin
local re_sub = ngx.re.sub
local re_match = ngx.re.match
local escape_uri = ngx.escape_uri
local log = ngx.log
local say = ngx.say
local ALERT = ngx.ALERT
local WARN = ngx.WARN
local INFO = ngx.INFO
local DEBUG = ngx.DEBUG
local ngxvar = ngx.var
local time = ngx.time

local FORBIDDEN_TEXT = string.format([[
<html>
<head><title>403 Forbidden</title></head>
<body>
<h1>403 Forbidden</h1>
<hr />
<p>Your access to the requested web site is temporarily blocked.</p>
</body>
</html>
%s
]], string.rep(" \n", 1024))

function get_timestamp()
    return tostring(math.floor(time()/300))
end

function get_timestamp_minute()
    return tostring(math.floor(time()/60))
end

local function zincr(name, ttl, incr)
    local incr = incr or 1
    local val, err = cache:incr(name, incr)
    if val == nil then
        local succ, err, forcible = cache:set(name, incr, ttl)
    	val = 1
    end
    return val
end

local function terminate(red)
    -- We can't set ngx.status here because we send response body in protectors and then
    -- we call terminate(). Otherwise we'd get "an attempt to set ngx.status after sending out response headers" error
    red:set_keepalive(100000, 100)
    ngx.ctx.terminated = 1
    ngx.exit(ngx.HTTP_OK)
end

local function incr_expire(red, zname, vname, ttl)
    local ttl = ttl or STAT_TTL
    red:zincrby(zname, 1, vname)
    red:expire(zname, ttl)
end

local function gen_cookie(prefix, rnd, server_name)
    return encode_base64(
        -- In order to separate different clients from the same IP and the same UserAgent we add a random number here
        escape_uri(sha1_bin(prefix .. SECRET .. rnd .. server_name))
    )
end

local function forbidden(red)
    ngx.header['Content-Type'] = "text/html; charset=utf-8"
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.say(FORBIDDEN_TEXT)
    terminate(red)
end

local function captcha(red, uid)
    if recaptcha.run() then -- true if captcha has been passed, false otherwise
        red:init_pipeline(4)
        red:del("cnt:" .. uid)
        red:del("ban:" .. uid)
        red:set("allow:" .. uid, 1) -- включим его в whitelist
        red:expire("allow:" .. uid, BAN_TTL)
        red:commit_pipeline()
        red:set_keepalive(100000, 100)
        ngx.ctx.terminated = 1 -- этот запрос все равно считать не надо, надо только следующий
        return ngx.redirect(ngxvar.request_uri)
    else
        terminate(red)
    end
end

local function check_search_engine_bot(red, bot, ip)
    if bot == "pass" then -- ничего не проверяем
        return true
    end

    local test, err = red:get("se:" .. ip)
    if test == "1" then
        red:expire("se:" .. ip, SE_TTL)
        return true
    end
    if test == "0" then
        return false
    end

    local r, err = resolver:new{
        nameservers = NAMESERVERS,
        retrans = 2,  -- 2 retransmissions on receive timeout
        timeout = 200,  -- 0.2 sec
    }
    local se_bots = {
        yandex = "\\.yandex\\.(ru|net|com)$",
        google = "\\.google(bot)?\\.com$",
        mail_ru = "\\.mail\\.ru$"
    }

    if not r then
        log(ALERT, "Failed to instantiate DNS resolver: ", err)
        return false
    end

    local ans_ptr, err = r:reverse_query(ip)

    if not ans_ptr then
        log(ALERT, "DNS resolver failed to query PTR: ", err)
        red:set("se:" .. ip, 0)
        red:expire("se:" .. ip, BAN_TTL)
        return false
    end

    local ptr_name = ""

    for i, ans in ipairs(ans_ptr) do
        if ans.ptrdname then
            ptr_name = ans.ptrdname
        end
    end

    if ptr_name == "" then
        log(DEBUG, "PTR resolving failed")
        return false
    end

    local ans_a, err = r:query(ptr_name, { qtype = r.TYPE_A })
    if not ans_a then
        log(ALERT, "DNS resolver failed to query A: ", err)
        red:set("se:" .. ip, 0)
        red:expire("se:" .. ip, BAN_TTL)
        return false
    end
    if ans_a.errcode then -- nonexistent domain
        log(ALERT, "Fake search engine bot '", bot, "': ptr=", ptr_name)
        red:set("se:" .. ip, 0)
        red:expire("se:" .. ip, SE_TTL)
        return false
    end

    local dns_a = ans_a[1].address or ''

    if dns_a == ip and re_match(ptr_name, se_bots[bot], "imjo") then
        log(ALERT, "Search engine bot '", bot, "': ptr=", ptr_name, ", dns_a=", dns_a, " = CONFIRMED")
        red:set("se:" .. ip, 1)
        red:expire("se:" .. ip, SE_TTL)
        return true
    end
    log(ALERT, "Fake search engine bot '", bot, "': ptr=", ptr_name, ", dns_a=", dns_a)
    red:set("se:" .. ip, 0)
    red:expire("se:" .. ip, SE_TTL)
    return false
end

function guard.access()
    if ngxvar.is_internal_redirect == "1" then
        return
    end

    local red = redis:new()
    red:set_timeout(200)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        ok, err = red:connect(REDIS_HOST, REDIS_PORT)
        if not ok then
            log(ALERT, "Failed to connect to redis after 2 tries:", err)
            return
        end
    end
    red:select(0)
    red:set_timeout(1000)

    local under_attack = ngxvar.under_attack or "0"
    local protected_url = ngxvar.protected_url or "0"
    local protection_disabled = ngxvar.protection_disabled or "0"
    local server_name = ngxvar.server_name or "localhost"
    if server_name == "" then -- server_name пустое, если запрос попал в catch-all server {} блок
        server_name = "localhost"
    end
    local host = ngxvar.http_host or ""
    local request_uri = ngxvar.request_uri or ""
    local request_method = ngxvar.request_method or "GET"
    local ip = ngxvar.remote_addr or ""
    local user_agent_full = ngxvar.http_user_agent or ""
    local user_agent = ""

    if user_agent_full ~= "" then
        user_agent = encode_base64(sha1_bin(user_agent_full))
    end
    local uid = ip .. ':' .. user_agent

    local timestamp = get_timestamp()
    local timestamp_minute = get_timestamp_minute()

    -- убираем из url все, что идет после "?..": /path/to/file.php?a=b => /path/to/file.php
    if ngxvar.is_args == '?' then
        local newstr, n, err = re_sub(request_uri, '^([^?]+)\\?.*$', '$1')
        request_uri = newstr
    end

    red:init_pipeline(16)

    -- хиты на сайтах: sites-hits:ALL:timestamp({domain1.ru: 10}, {domain2.ru: 5})
    incr_expire(red, "sites-hits:ALL:" .. timestamp, server_name)
    incr_expire(red, "sites-hits:" .. request_method .. ":" .. timestamp, server_name)

    -- хиты на сайте по алиасам
    incr_expire(red, "aliases-hits:" .. server_name .. ":" .. timestamp, host)

    -- таблица соответствий шифрованного user-agent реальному
    red:set("UA:" .. user_agent, user_agent_full)
    red:expire("UA:" .. user_agent, STAT_TTL)

    -- хиты на страницах сайтов sites-pages:domain2.ru:get:timestamp({url1: 10}, {url2: 5})
    incr_expire(red, "site-pages:" .. server_name .. ":" .. timestamp, request_method .. " " .. request_uri)

    -- хиты с IP:UA на сайтах: sites-ips:domain2.ru:get:timestamp({ip1: 10}, {ip2: 5})
    incr_expire(red, "site-ips:" .. server_name .. ":" .. timestamp, uid)

    -- хиты с IP:UA на страницах сайтов: urls-ips:domain2.ru:/url:get:timestamp({ip1: 10}, {ip2: 5})
    incr_expire(red, "url-ips:" .. server_name .. ":" .. request_uri .. ":" .. timestamp, uid)

    -- какие страницы посещались с IP:UA: ip-pages:ip:get:timestamp({domain1.ru/url: 10}, ...)
    incr_expire(red, "ip-pages:" .. uid .. ":" .. timestamp, request_method .. " " .. server_name .. request_uri)

    red:commit_pipeline()

    local search_engine_bot = false
    if ngxvar.is_search_engine_ua ~= "0" then
        search_engine_bot = check_search_engine_bot(red, ngxvar.is_search_engine_ua, ip)
    end

    if search_engine_bot or ngxvar.whitelisted ~= "0" or protection_disabled == "1" or request_method == "HEAD" then
        red:set_keepalive(100000, 100)
        return
    end

    -- Проверяем uid в бан-листе
    local ban, err = red:get("ban:" .. uid)
    if ban == "1" then
        incr_expire(red, "site-bots:" .. timestamp, server_name)
        captcha(red, uid)
    end

    -- check if ip has reached limit_hits_per_ip
    if zincr(ip .. ":" .. timestamp_minute, 65) > tonumber(ngxvar.limit_hits_per_ip) then
        log(ALERT, "LIMIT_HITS_PER_IP reached for ", ip, ", ", uid, ", ", user_agent_full)
        incr_expire(red, "site-bots:" .. timestamp, server_name)
        forbidden(red)
    end

    -- Check if website has reached limit_hits_per_vhost
    if zincr(server_name .. ":" .. timestamp_minute, 65) > tonumber(ngxvar.limit_hits_per_vhost) then
        log(ALERT, "LIMIT_HITS_PER_VHOST reached for ", ip, ", ", uid, ", ", user_agent_full)
        if under_attack == "0" then
            local m, err = re_match(request_uri, "\\.(jpg)|(png)|(gif)|(css)|(js)|(woff)|(ico)$", "imjo")
            if m == nil then -- включаем защиту до конца текущей минуты, если это запрос не к статике
                under_attack = "htmlcookie"
            end
        end
    end

    -- Проверяем uid в списке разгадавших капчу
    local allow, err = red:get("allow:" .. uid)
    if allow == "1" then
        red:expire("allow:" .. uid, BAN_TTL) -- продляем действие allow:uid
    end


    if allow == "1" or (under_attack == "0" and protected_url == "0") then
        red:set_keepalive(100000, 100)
        return
    end

    -- мы оказались тут только в случае ddos или protected_url, но не в случае HEAD-запросов

    if under_attack == "captcha" or protected_url == "captcha" then
        captcha(red, uid)
    end

    local cookie_domain, n, err = re_sub(host, '^(www\\.)?(.*)$', '.$2', "imjo")


    -- Проверяем есть ли кука и если есть, правильная ли она
    local user_cookie = ngx.unescape_uri(ngxvar['cookie_' .. USER_COOKIE_NAME]) or ''
    local rnd = 0
    -- значение куки имеет формат ШИФР_RND. Извлекаем RND из куки или генерируем новый RND
    local p = user_cookie:find('_')
    if p then
        rnd = user_cookie:sub(p+1)
        user_cookie = user_cookie:sub(1, p-1)
    else
        rnd = tostring(math.random(2147483647))
    end

    local control_cookie = gen_cookie(uid, rnd, server_name)

    if user_cookie ~= control_cookie then
        -- мы оказались тут только если cookie была неправильная или отсутствовала
        user_cookie = ''
        -- увеличиваем счетчик попыток произвести проверку
        local cnt, err = red:incr("cnt:" .. uid)
        red:expire("cnt:" .. uid, 300)

        if cnt > 3 then
            -- лимит исчерпан, иди в бан
            red:del("cnt:" .. uid)
            red:set("ban:" .. uid, 1)
            red:expire("ban:" .. uid, BAN_TTL)
            red:expire("UA:" .. user_agent, BAN_TTL)  -- неплохо помнить UA для забаненных в течение BAN_TTL, а не STAT_TTL
            incr_expire(red, "site-bots:" .. timestamp, server_name)
            log(ALERT, 'Banned bot: "' .. uid .. '", under_attack: ' .. under_attack .. ', protected_url: ' .. protected_url)
            captcha(red, uid)
        end

        local protector
        if protected_url ~= "0" then
            protector = protected_url
            log(ALERT, 'Protected URL access: "' .. uid .. '", User-Agent: ' .. user_agent_full)
        else
            protector = under_attack
        end

        protectors[protector](control_cookie, rnd, cookie_domain)
        terminate(red)
    end
    red:set_keepalive(100000, 100)
    return
end

function guard.finish()
    if ngx.ctx.terminated == 1 then
        return
    end

    local server_name = ngxvar.server_name or 'localhost'

    local timestamp = get_timestamp()
    local hit_code = "unknown"
    local status = ngx.status

    if status >= 200 and status < 300 then
        hit_code = "2xx"
    elseif status >= 300 and status < 400 then
        hit_code = "3xx"
    elseif status >= 400 and status < 500 then
        hit_code = "4xx"
    elseif status == 500 then
        hit_code = "500"
    elseif status > 500 then
        hit_code = "5xx"
    end

    --incr_hits(server_name, hit_code, timestamp, 350)
    zincr(server_name .. ":" .. hit_code .. ":" .. timestamp, 350)
    zincr(server_name .. ":all:" .. timestamp, 350)
end

function guard.get_cache()
    local timestamp = ngx.var["arg_timestamp"]
    local server_name = ngx.var["arg_server_name"]
    if timestamp == nil then
        timestamp = get_timestamp()
    end
    local codes = {["all"] = "hits", ["2xx"] = "hits_2xx", ["3xx"] = "hits_3xx", ["4xx"] = "hits_4xx", ["500"] = "hits_500",
        ["5xx"] = "hits_5xx"}
    local val, err, i, name
    for i, name in pairs(codes) do
        val, err = cache:get(server_name .. ":" .. i .. ":" .. timestamp)
        if val ~= nil and val > 0 then
            say(name .. " " .. val)
        end
    end
end

return guard
