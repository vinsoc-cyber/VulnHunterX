package main

import (
	"net/http"

	"github.com/antchfx/xmlquery"
)

func search(doc *xmlquery.Node, r *http.Request) {
	_ = r
	xmlquery.Find(doc, "//user[@active='true']")
}
