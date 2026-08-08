<?php

require_once __DIR__ . '/store.php';

function show($code) {
    return lookup($code);
}
