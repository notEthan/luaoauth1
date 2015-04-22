lapis = require("lapis")
app = lapis.Application()

app\get "/", =>
  {"☺", content_type: "text/plain; charset=UTF-8", layout: false}
app\put "/", =>
  {"☺", content_type: "text/plain; charset=UTF-8", layout: false}
app\post "/", =>
  {"☺", content_type: "text/plain; charset=UTF-8", layout: false}
app
