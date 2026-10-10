<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

require_once __DIR__ . '/store.php';

Route::get('/show', function (Request $request) {
    return show($request->query('code', ''));
});

function show($code) {
    return lookup($code);
}
