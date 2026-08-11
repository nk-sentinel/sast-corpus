import logging

logger = logging.getLogger(__name__)


def record(user, password):
    logger.info("sign-in user=%s", user)
    return True
