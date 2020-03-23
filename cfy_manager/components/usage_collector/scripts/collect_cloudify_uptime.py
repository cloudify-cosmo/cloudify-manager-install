from script_utils import (logger,
                          send_data,
                          HOURS_INTERVAL,
                          collect_metadata,
                          needs_to_send_data)


CLOUDIFY_ENDPOINT_UPTIME_URL = 'https://api.cloudify.co/cloudifyUptime'


def main():
    if needs_to_send_data(HOURS_INTERVAL):
        logger.info('Uptime script started running')
        data = {}
        collect_metadata(data)
        send_data(data, CLOUDIFY_ENDPOINT_UPTIME_URL, HOURS_INTERVAL)
        logger.info('Uptime script finished running')


if __name__ == '__main__':
    main()
