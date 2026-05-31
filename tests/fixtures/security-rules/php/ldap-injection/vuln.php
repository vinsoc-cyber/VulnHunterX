<?php
ldap_search($conn, 'dc=example,dc=com', '(uid=' . $_GET['user'] . ')');
