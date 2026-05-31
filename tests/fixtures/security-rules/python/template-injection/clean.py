from flask import render_template_string

def page():
    return render_template_string("<h1>Welcome</h1>")
