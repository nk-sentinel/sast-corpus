<?php

define('DB_PASSWORD', 'Pr0d-Repor7ing-2024!');

function render($user) {
    return $user . ':' . DB_PASSWORD;
}
