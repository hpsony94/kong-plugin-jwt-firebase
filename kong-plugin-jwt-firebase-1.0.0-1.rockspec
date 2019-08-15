package = "kong-plugin-jwt-firebase"
version = "1.0.0-1"
source = {
  url = "https://github.com/hpsony94/kong-plugin-jwt-firebase",
}
description = {
  summary = "This plugin allows Kong to verify JWT Firebase Token.",
  license = "Apache 2.0"
}
dependencies = {
  "lua >= 5.1",
  --"kong >= 1.1"
}
build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-firebase.handler"] = "kong/plugins/jwt-firebase/handler.lua",
    ["kong.plugins.jwt-firebase.schema"]  = "kong/plugins/jwt-firebase/schema.lua",
    ["kong.plugins.jwt-firebase.constants"] = "kong/plugins/jwt-firebase/constants.lua"
  }
}

