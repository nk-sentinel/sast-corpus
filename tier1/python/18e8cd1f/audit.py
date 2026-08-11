import logging

logger = logging.getLogger(__name__)


def record(user, password):
    logger.info("sign-in user=%s password=%s", user, password)
    return True
