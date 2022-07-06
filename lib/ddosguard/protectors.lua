-- Copyright (C) Anton Khalikov (antony66), NetAngels.RU

local utils = require "ddosguard.utils"

local str_fmt = string.format
local escape_uri = ngx.escape_uri
local say = ngx.say
local log = ngx.log
local ngxvar = ngx.var

local protectors = {
}

function protectors.htmlcookie(control_cookie, rnd, cookie_domain)
    utils.send_nocache_headers()
    utils.send_cookie(control_cookie, rnd, cookie_domain)
    say([[
<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8" /><meta name="viewport" content="width=960" /><title>NetAngels DDoS Protection</title><style>html{-webkit-text-size-adjust: none}body{font-family:Arial, sans-serif;font-size:16px;color:#343434;text-align: center;min-height: 100%;background: #F7F7F7}img{border:none;margin:50px auto}a{text-decoration:underline;color:#9ABFCF;text-align:center;font-size:14px}.title{color:#769cad;font-size:37px;font-weight:bold;width:960px;margin:30px auto 10px}.text{width:960px;margin:0 auto;line-height:25px}.link{display:block;position:absolute;bottom:0;left:0;width:100%;padding:20px 0}</style><meta http-equiv="refresh" content="2" /></head><body><div class="title">Производится проверка вашего браузера для доступа к этому сайту</div><div class="text">Этот процесс происходит автоматически. Вскоре браузер перенаправит вас на запрошенную страницу.<br>Пожалуйста, подождите несколько секунд...</div><img src="https://www.netangels.ru/static/images/ajax-loader.gif"><div class="link"><a href="http://www.netangels.ru/">NetAngels DDoS Protection</a></div></body></html>
    ]])
end

function protectors.jscookie(control_cookie, rnd, cookie_domain)
    utils.send_nocache_headers()
    say(str_fmt([[
<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8" /><meta name="viewport" content="width=960" /><title>NetAngels DDoS Protection</title><style>html{-webkit-text-size-adjust: none}body{font-family:Arial, sans-serif;font-size:16px;color:#343434;text-align: center;min-height: 100%%;background: #F7F7F7}img{border:none;margin:50px auto}a{text-decoration:underline;color:#9ABFCF;text-align:center;font-size:14px}.title{color:#769cad;font-size:37px;font-weight:bold;width:960px;margin:30px auto 10px}.text{width:960px;margin:0 auto;line-height:25px}.link{display:block;position:absolute;bottom:0;left:0;width:100%%;padding:20px 0}</style></head><body><script>setTimeout(function(){document.cookie="%s=%s"+"_%s; max-age=%d; path=/; domain=%s"; window.location.reload(true);}, 2000);</script>
<div class="title">Производится проверка вашего браузера для доступа к этому сайту</div><div class="text">Этот процесс происходит автоматически. Вскоре браузер перенаправит вас на запрошенную страницу.<br>Пожалуйста, подождите несколько секунд...</div><img src="https://www.netangels.ru/static/images/ajax-loader.gif"><div class="link"><a href="http://www.netangels.ru/">NetAngels DDoS Protection</a></div></body></html>
    ]], USER_COOKIE_NAME, control_cookie, rnd, USER_COOKIE_TTL, cookie_domain))
end

return protectors
