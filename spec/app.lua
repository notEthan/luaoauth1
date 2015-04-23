local lapis = require("lapis")
local app = lapis.Application()
app:get("/", function(self)
  return {
    "☺",
    content_type = "text/plain; charset=UTF-8",
    layout = false
  }
end)
app:put("/", function(self)
  return {
    "☺",
    content_type = "text/plain; charset=UTF-8",
    layout = false
  }
end)
app:post("/", function(self)
  return {
    "☺",
    content_type = "text/plain; charset=UTF-8",
    layout = false
  }
end)
return app
