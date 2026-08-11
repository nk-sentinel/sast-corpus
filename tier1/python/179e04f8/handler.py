import logging

from store import lookup

logger = logging.getLogger(__name__)


def show(code):
    try:
        return lookup(code)
    except Exception:
        logger.exception("lookup failed")
        return "lookup failed"
