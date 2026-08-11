<?php

function render($user) {
    return $user . ':' . getenv('DB_PASSWORD');
}
