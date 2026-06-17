import jinja2

# Autoescape enabled — output is HTML-escaped by default.
env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"), autoescape=True)
