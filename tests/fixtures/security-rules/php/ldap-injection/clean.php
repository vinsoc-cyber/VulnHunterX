<?php
$user = ldap_escape($_GET['user'], '', LDAP_ESCAPE_FILTER);
ldap_search($conn, 'dc=example,dc=com', '(uid=' . $user . ')');
