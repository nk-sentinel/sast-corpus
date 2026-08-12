<?php

define('CURRENT_USER', 'alice');
$OWNERS = ['A-1001' => 'alice', 'A-1002' => 'bob'];

function render($orderId) {
    global $OWNERS;
    if (($OWNERS[$orderId] ?? null) !== CURRENT_USER) {
        return '';
    }
    return fetchOrder($orderId);
}

function fetchOrder($orderId) {
    return "order $orderId contents";
}
