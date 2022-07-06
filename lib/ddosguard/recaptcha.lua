-- Copyright (C) Anton Khalikov (antony66), NetAngels.RU

local cjson = require "cjson"
local utils = require "ddosguard.utils"
local http = require "resty.http"
local str_fmt = string.format
local say = ngx.say
local log = ngx.log
local ngxvar = ngx.var

local recaptcha = {}

function recaptcha.run(red, uid)
    local request_method = ngxvar.request_method
    local host = ngxvar.http_host or ''
    local ip = ngxvar.remote_addr
    local passed = false
    local result = ""
    local err = ""
    local args = ""
    if request_method == "POST" then
        ngx.req.read_body()
        args, err = ngx.req.get_post_args()
        if not args or args["g-recaptcha-response"] == nil then
            err = "<p>Возникла ошибка чтения данных из запроса. Пожалуйста, попробуйте еще раз.</p>"
            log(ngx.ERR, "Recaptcha error:", err)
        else
            local httpc = http.new()
            result, err = httpc:request_uri("https://www.google.com/recaptcha/api/siteverify", {
                method = "POST",
                body = "secret=" .. RECAPTCHA_PRIVATE .. "&remoteip=" .. ip .. "&response=" .. args["g-recaptcha-response"],
                headers = {
                    ["Content-Type"] = "application/x-www-form-urlencoded",
                },
                ssl_verify = false,
            })
            if err then
                err = "<p>Возникла ошибка: " .. err .. " Пожалуйста, попробуйте еще раз.</p>"
                log(ngx.ERR, "Recaptcha error:", err)
            else
                local json = cjson.new()
                result = json.decode(result.body)
                if result["success"] then
                    passed = true
                else
                    err = "Капча разгадана неверно. Попробуйте еще раз."
                end
            end
        end
    end
    if passed ~= true then
        utils.send_nocache_headers()
        if err ~= "" then
            err = "<br /><div class=\"text\" style=\"color: red\">" .. err .. "</div>"
        end
        say(str_fmt([[
<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8" /><meta name="viewport" content="width=960" /><title>NetAngels DDoS Protection</title><style>html{-webkit-text-size-adjust: none}body{font-family:Arial, sans-serif;font-size:16px;color:#343434;text-align: center;min-height: 100%%;background: #F7F7F7}a{text-decoration:underline;color:#9ABFCF;text-align:center;font-size:14px}.title{color:#769cad;font-size:32px;font-weight:bold;width:960px;margin:30px auto 10px}.text{width:960px;margin:0 auto;line-height:25px}.link{display:block;position:absolute;bottom:0;left:0;width:100%%;padding:20px 0}form{display:block;margin:45px auto;width:318px}input[type="submit"]{margin: 15px 0 0;padding:6px 20px;cursor:pointer}</style>
<script src="https://www.google.com/recaptcha/api.js?hl=ru" async defer></script></head><body><div class="title">Для доступа к сайту %s требуется авторизация</div>%s<form action="" method="post"><div class="g-recaptcha" data-sitekey="%s"></div>
<br/><input type="submit" value="Да!"></form><div class="link"><a href="http://www.netangels.ru/">NetAngels DDoS Protection</a></div></body></html>
        ]], host, err, RECAPTCHA_PUBLIC))
    end
    -- возвращаем true при правильно разгаданной капче, иначе false
    return passed
end

return recaptcha
