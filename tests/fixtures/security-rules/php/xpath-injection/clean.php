<?php
$xpath = new DOMXPath($doc);
$nodes = $xpath->query("//user[@active=\"true\"]");
