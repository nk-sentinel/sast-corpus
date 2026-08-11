<?php

function render($name) {
    $encoded = htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    return "<div class='row'>" . $encoded . "</div>";
}
