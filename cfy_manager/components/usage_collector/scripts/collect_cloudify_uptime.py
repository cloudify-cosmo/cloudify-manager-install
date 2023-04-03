from script_utils import (
    logger,
    send_data,
    HOURS_LOCK,
    HOURS_INTERVAL,
    collect_metadata,
    should_send_data,
    usage_collector_lock,
    setup_appctx,
)


CLOUDIFY_ENDPOINT_UPTIME_URL = 'https://api.cloudify.co/cloudifyUptime'


def main():
    with usage_collector_lock(HOURS_LOCK) as locked:
        if not locked:
            logger.info('Other Manager is currently updating cloudify_uptime')
            return
        logger.debug('Acquired usage_collector table lock')
        if should_send_data(HOURS_INTERVAL):
            logger.info('Uptime script started running')
            data = {}
            collect_metadata(data)
            send_data(data, CLOUDIFY_ENDPOINT_UPTIME_URL, HOURS_INTERVAL)
            logger.info('Uptime script finished running')
        else:
            logger.info('cloudify_uptime was updated by a different Manager')


if __name__ == '__main__':
    with setup_appctx():
        main()
