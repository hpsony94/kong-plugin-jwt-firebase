local constants = require "kong.constants"
local local_constants = require "kong.plugins.jwt-firebase.constants"
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"


local shm = "/dev/shm/kong.jwt-firebase.pubkey"
local fmt = string.format
local kong = kong
local type = type
local ipairs = ipairs
local tostring = tostring
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match
local ngx_set_header = ngx.req.set_header

local JwtHandler = {}


JwtHandler.PRIORITY = 70
JwtHandler.VERSION = "1.0.0"

--- Grab a public key from google api by the kid value
-- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com 
-- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response 
-- from that endpoint to know when to refresh the public keys.
local function grab_public_key_bykid(t_kid)
  kong.log.debug("### grab_public_key_bykid() " .. t_kid)
  kong.log.debug("### Grabbing pubkey from google ..")
  local google_url = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
  local magic = " | cut -d \"\\\"\" -f4- | sed 's/\\\\n/\\n/g\' | sed 's/\"//g' | openssl x509 -pubkey -noout"
  local cmd = "wget -qO - " .. google_url .. " | grep -i " .. t_kid .. magic

  kong.log.debug("### cmd: " .. cmd)
  local cmd_handle = io.popen(cmd)
  local public_key = cmd_handle:read("*a")
  cmd_handle:close()
  kong.log.debug ("### public_key : " .. public_key)

  return public_key
end


--- Push public key into /dev/shm
local function push_public_key_into_file(publickey, dir)
  kong.log.debug("### push_public_key_into_file() - " .. publickey .. " - "  .. dir)
  local cmd = "echo -n \"" .. publickey .. "\" > " .. shm
  kong.log.debug("### cmd: " ..  cmd)

  local cmd_handle, err = io.popen(cmd)
  if not cmd_handle then
    cmd_handlel:close()
    return false
  end
  cmd_handle:close()
  return true
end

--- Get the public key from /dev/shm
local function get_public_key_from_file(dir)
  kong.log.debug("### get_public_key_from_file(): " .. dir)
  local file, err = io.open(dir, "r")
  if not file then
    return nil
  end
  io.input(file)
  content = io.read("*a")
  io.close(file)
  return content
end

--- Retrieve a JWT in a request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the `Authorization` header.
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function retrieve_token(conf)
  local args = kong.request.get_query()
  for _, v in ipairs(conf.uri_param_names) do
    if args[v] then
      return args[v]
    end
  end

  local var = ngx.var
  for _, v in ipairs(conf.cookie_names) do
    local cookie = var["cookie_" .. v]
    if cookie and cookie ~= "" then
      return cookie
    end
  end

  local authorization_header = kong.request.get_header("authorization")
  if authorization_header then
    local m, err = re_match(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not m then
      return authorization_header
    end
    local iterator, iter_err = re_gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
    if not iterator then
      return nil, iter_err
    end

    local m, err = iterator()
    if err then
      return nil, err
    end

    if m and #m > 0 then
      return m[1]
    end
  end
end


--- do_authentication is to verify JWT firebase token
---   ref to: https://firebase.google.com/docs/auth/admin/verify-id-tokens
local function do_authentication(conf)
  local token, err = retrieve_token(conf)
  if err then
    kong.log.err(err)
    return kong.response.exit(500, { message = "An unexpected error occurred" })
  end
  
  local token_type = type(token)
  if token_type ~= "string" then
    if token_type == "nil" then
      return false, { status = 401, message = "Unauthorized" }
    elseif token_type == "table" then
      return false, { status = 401, message = "Multiple tokens provided" }
    else
      return false, { status = 401, message = "Unrecognizable token" }
    end
  end

  -- Decode token
  local jwt, err = jwt_decoder:new(token)
  if err then
    return false, { status = 401, message = "Bad token; " .. tostring(err) }
  end

  local claims = jwt.claims
  local header = jwt.header

  -- Verify Header
  -- -- Verify "alg"
  local hd_alg = jwt.header.alg
  kong.log.debug("### header.alg: " .. hd_alg)
  if not hd_alg or hd_alg ~= "RS256" then
    return false, { status = 401, message = "Invalid algorithm" }
  end
 
  -- Verify Payload
  -- -- Verify "iss"
  local pl_iss = jwt.claims.iss
  kong.log.debug("### payload.iss : " .. pl_iss)
  local conf_iss = "https://securetoken.google.com/" .. conf.project_id
  kong.log.debug("### conf_iss: " .. conf_iss)
  if not pl_iss or pl_iss ~= conf_iss then
    return false, { status = 401, message = "Invalid iss in the header" }
  end
  -- -- Verify the "aud"
  local pl_aud = jwt.claims.aud
  kong.log.debug("### payload.aud: " .. pl_aud)
  kong.log.debug("### conf.project_id: " .. conf.project_id)
  if not pl_aud or pl_aud ~= conf.project_id then
    return false, { status = 401, message = "Invalid aud in the header"}
  end
  -- -- Verify the "exp" 
  kong.log.debug("### Checking exp ... ")
  local ok_claims, errors = jwt:verify_registered_claims(conf.claims_to_verify)
  if not ok_claims then
    return false, { status = 401, errors = errors }
  end
  -- -- Verify the "exp" with "maximum_expiration" value
  kong.log.debug("### Checking additional maximum expiration ...")
  if conf.maximum_expiration ~= nil and conf.maximum_expiration > 0 then
    local ok, errors = jwt:check_maximum_expiration(conf.maximum_expiration)
    if not ok then
      return false, { status = 401, errors = errors }
    end
  end

  -- -- Verify the "sub" must be non-empty
  local pl_sub  = jwt.claims.sub
  kong.log.debug("### payload.sub: " .. pl_sub)
  if not pl_sub then
    return false, { status = 401, message = "the sub must be non-empty in the header" }
  end
  -- -- Pud user-id into request header
  if conf.uid_inreq_header then
    ngx_set_header(local_constants.HEADERS.TOKEN_USER_ID, pl_sub)
    kong.log.debug("### Set " .. local_constants.HEADERS.TOKEN_USER_ID .. ": " .. pl_sub .. "in the request header")
  end



  -- Finally -- Verify the signature
  -- Finally, ensure that the ID token was signed by the private key corresponding to the token's kid claim. 
  -- Grab the public key from https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com 
  -- and use a JWT library to verify the signature. Use the value of max-age in the Cache-Control header of the response 
  -- from that endpoint to know when to refresh the public keys.
  -- Now verify the JWT signature
  local kid = jwt.header.kid
  -- -- Get public key in memory file
  -- -- -- if it is invalied or empty
  -- -- -- -- grabs a new public key from google api
  -- -- -- -- push this key into memory file
  -- -- -- -- assign this key to public_key
  local public_key = get_public_key_from_file(shm)
  kong.log.debug(public_key)
  if public_key == nil then
    kong.log.info("Public key in a file is empty or invalid")
    --local t_public_key = grab_1st_public_key()
    local t_public_key = grab_public_key_bykid(kid)
    local ok, err = push_public_key_into_file(t_public_key, shm)
    if not ok then
      kong.log.err("### ERROR: Failed to push a new publish key into SHM dir! FIX IT NOW")
    end
    public_key = t_public_key
  end
  -- -- By using jwt lib to verify signature
  -- -- If failed
  -- -- -- grab a new public key from the google api 
  -- -- -- store this public key into memory file if it verifies  successful at 2nd time
  if not jwt:verify_signature(public_key) then
    kong.log.debug("### Grabbing pubkey from google URL ...")
    local t_public_key = grab_public_key_bykid(kid)
    if jwt:verify_signature(t_public_key) then
      local ok, err = push_public_key_into_file(t_public_key, shm)
      if not ok then
        kong.log.err("### ERROR: Failed to push a new publish key into SHM dir! FIX IT NOW")
      end
      return true
    end
    return false, { status = 401, message = "Invalid signature" }
  end
  return true
end


function JwtHandler:access(conf)
  local ok, err = do_authentication(conf)
  if not ok then
    return kong.response.exit(err.status, err.errors or { message = err.message })
  end
end


return JwtHandler
