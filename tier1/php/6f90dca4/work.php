<?php

define('CURRENT_USER', 'alice');

function render($orderId) {
    return fetchOrder($orderId);
}

function fetchOrder($orderId) {
    return "order $orderId contents";
}
