import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    # TODO implement
    logger.info("event: {}".format(event))    
    print 'Hello from Lambda'
