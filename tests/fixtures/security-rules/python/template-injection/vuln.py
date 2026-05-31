from flask import render_template_string, request

def page():
    name = request.args.get("name")
    return render_template_string("<h1>" + name + "</h1>")
