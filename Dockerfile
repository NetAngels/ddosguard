FROM openresty/openresty:buster

LABEL maintainer="noc@netangels.ru"
LABEL description="Openresty based http(s) flood DDoS protection"

COPY nginx /etc/nginx
COPY lib/ddosguard /usr/local/openresty/lualib/ddosguard
COPY lib/lua-resty-http/lib/resty /usr/local/openresty/lualib/resty
