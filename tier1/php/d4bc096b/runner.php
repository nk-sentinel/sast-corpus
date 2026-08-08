<?php

function archive($name) {
    $line = 'tar -cf backup.tar ' . $name;
    return shell_exec($line);
}
