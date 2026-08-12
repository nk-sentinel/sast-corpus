<?php

function render($user) {
    $flat = str_replace(["\r", "\n"], '', $user);
    return 'level=info action=login user=' . $flat;
}
