package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

func search(doc *xmlquery.Node, r *http.Request) {
	name := r.URL.Query().Get("name")
	xmlquery.Find(doc, "//user[@name='"+name+"']")
}
