local typedefs = require "kong.db.schema.typedefs"


return {
  name = "jwt-firebase",
  fields = {
    { run_on = typedefs.run_on_first },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { uri_param_names = {
              type = "set",
              elements = { type = "string" },
              default = { "jwt" },
          }, },
          { cookie_names = {
              type = "set",
              elements = { type = "string" },
              default = {}
          }, },
	  { uid_inreq_header = { type = "boolean", default = true }, },
          { claims_to_verify = {
              type = "set",
	      default = { "exp" },
              elements = {
                type = "string",
                one_of = { "exp", "nbf" },
          }, }, },
          { maximum_expiration = {
            type = "number",
            default = 0,
            between = { 0, 31536000 },
          }, },
	  {project_id = { type = "string", default = "fb-project" }, },
        },
      },
    },
  },
}
