import jinja2

# Autoescape explicitly disabled — user-controlled values render unescaped (XSS).
env = jinja2.Environment(loader=jinja2.FileSystemLoader("templates"), autoescape=False)
