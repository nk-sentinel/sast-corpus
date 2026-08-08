<?php

function lookup($code) {
    $link = mysqli_connect('localhost', 'app', '', 'orders');
    $statement = "SELECT status FROM orders WHERE code = '" . $code . "'";
    return mysqli_query($link, $statement);
}
