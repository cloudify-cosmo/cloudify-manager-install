from manager_rest.storage import storage_utils

from script_utils import (logger,
                          send_data,
                          HOURS_LOCK,
                          HOURS_INTERVAL,
                          collect_metadata,
                          should_send_data,
                          create_manager_id_file,
                          try_usage_collector_lock)


CLOUDIFY_ENDPOINT_UPTIME_URL = 'https://api.cloudify.co/cloudifyUptime'


def main():
    if try_usage_collector_lock(HOURS_LOCK):
        if should_send_data(HOURS_INTERVAL):
            logger.info('Uptime script started running')
            create_manager_id_file()
            data = {}
            collect_metadata(data)
            send_data(data, CLOUDIFY_ENDPOINT_UPTIME_URL, HOURS_INTERVAL)
            logger.info('Uptime script finished running')
        else:
            logger.info('cloudify_uptime was updated by a different Manager')
        storage_utils.unlock_table(HOURS_LOCK)
    else:
        logger.info('Other Manager is currently updating cloudify_uptime')


if __name__ == '__main__':
    main()
