const handlebars = require("handlebars");
function render(req) {
  return handlebars.compile("<h1>" + req.query.name + "</h1>");
}
