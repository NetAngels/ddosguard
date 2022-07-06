# DDoSGuard: http flood DDoS protection

DDoSGuard is a pretty old yet effective solution to filter http(s) flood DDoS attacks. The core of the project is written in LUA and is heavily based on Openresty libraries.

DDoSGuard requires Redis as a database backend.

## Configuration

DDoSGuard has a lot of tweakable config files. Main configuration file is `nginx/conf.d/99_ddosguard.conf`. Open it and change `SECRET`, `RECAPTCHA_PUBLIC` and `RECAPTCHA_PRIVATE` keys. Don't forget to mount edited file inside your Docker container as demonstrated in `docker-compose.yml.example`.

Any website that needs a permanent protection should be added to `nginx/under_attack` as follows:

    domain.ru "strategy";

There are 3 protection strategies available:

* `htmlcookie` - basic protection against base level bots that don't read generated output. It sets up a test cookie and then checks if this cookie is present in the following requests.
* `jscookie` - more advanced, JavaScript based mechanism that sets up a test cookie.
* `captcha` - any visitor is required to solve Recaptcha to access website. No cookies used. Allowed visitors are stored in Redis based on their IP and User-Agent.

Feel free to contribute your own strategies.

If you need to protect some urls on every proxied web site (i.e. Wordpress admin areas), add their urls to `nginx/protected_urls` following the examples provided.

Per IP/network and per User-Agent whitelists are also possible: edit `nginx/whitelisted_networks` and `nginx/whitelisted_user_agents` accordingly.

Don't forget to reload nginx after every update you've made to config files like so:

    docker exec ddosguard_nginx_1 nginx -s reload


## Installation

The easiest way to get DDoSGuard up and running is to set it up as a Docker container:

```
cp docker-compose.yml.example docker-compose.yml
docker-compose up
```

It is also possible to run DDoSGuard without Docker. It requires nginx with LUA module compiled against libluajit (liblua is not supported) and a set of Openresty LUA libraries that can been copied from `/usr/local/openresty/lualib` folder from our Docker image.


## Example

There's a test web site `domain.ru` configured in `nginx/conf.d/sites.conf`. If everything has been set up correctly you should get a protection page html by running:

    curl -v -H 'Host: domain.ru' localhost

Then copy and paste the received protection cookie value:

    curl -v -H 'Host: domain.ru' -H '__test_req_cookie=<PASTE_COOKIE_VALUE_HERE>' localhost

Now, DDoSGuard should pass your request to the proxied web site.
