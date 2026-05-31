<?php
$xpath = new DOMXPath($doc);
$nodes = $xpath->query("//user[@name='" . $_GET['name'] . "']");
