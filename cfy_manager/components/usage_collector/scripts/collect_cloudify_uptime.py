from script_utils import (logger,
                          send_data,
                          collect_metadata,
                          create_manager_id_file)


CLOUDIFY_ENDPOINT_UPTIME_URL = 'https://api.cloudify.co/cloudifyUptime'


def main():
    logger.info('Uptime script started running')
    create_manager_id_file()
    data = {}
    collect_metadata(data)
    send_data(data, CLOUDIFY_ENDPOINT_UPTIME_URL)
    logger.info('Uptime script finished running')


if __name__ == '__main__':
    main()
