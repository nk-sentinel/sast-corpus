<?php

function render($name) {
    return file_get_contents('/srv/reports/' . $name);
}
