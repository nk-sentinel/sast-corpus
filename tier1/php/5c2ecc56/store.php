<?php

function lookup($code) {
    $link = mysqli_connect('localhost', 'app', '', 'orders');
    $statement = mysqli_prepare($link, 'SELECT status FROM orders WHERE code = ?');
    mysqli_stmt_bind_param($statement, 's', $code);
    mysqli_stmt_execute($statement);
    return mysqli_stmt_get_result($statement);
}
