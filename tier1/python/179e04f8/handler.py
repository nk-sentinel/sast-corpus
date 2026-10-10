import logging

from flask import Flask, request

from store import lookup

app = Flask(__name__)
logger = logging.getLogger(__name__)


@app.route("/show")
def show():
    try:
        return lookup(request.args.get("code", ""))
    except Exception:
        logger.exception("lookup failed")
        return "lookup failed"
