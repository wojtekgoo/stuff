from VT_detections_whitelist import validate_vt_url_ioc
from links import logger, api_key_vt, three_days_expired_domains_carrier, today_expired_domains_carrier, \
    checked_expired_domains, project_path_arc, webhook
import argparse
from general_tools import create_json_summary_data, update_domain_csv, move_old_file_to_arc, json_summary_data
from check_new_carrier_intel import check_domain_terminal
from carrier_expired_domains import retrieve_entries


def main():
    domain_name = {}
    summary_data = {}
    #new
    count = 0
    today_new_domains = update_domain_csv(today_expired_domains_carrier, checked_expired_domains)
    three_days_new_domains = update_domain_csv(three_days_expired_domains_carrier, checked_expired_domains)
    new_domains = today_new_domains + three_days_new_domains
    #new
    logger.info("Number of domains start: %s", len(new_domains))

    for domain in new_domains:
        # new
        count += 1
        check_carrier_intel = check_domain_terminal(domain)
        vt_detections = validate_vt_url_ioc(domain, api_key_vt)
        domain_name["Domain name"] = domain
        summary_data_domain = {**domain_name, **vt_detections, **check_carrier_intel}
        create_json_summary_data(summary_data_domain, domain)
        summary_data[domain] = summary_data_domain

        logger.info("Done : " + domain)
    #new
    logger.info("Number of domains end: %s", len(count))

    json_summary_data(summary_data)
    return summary_data


if __name__ == '__main__':
    while True:

        today, upcoming = retrieve_entries()
        results_today = ''.join([
            str(today)[:-1].replace(',', '\n'),
        ])

        results_upcoming = ''.join([
            str(upcoming)[:-1].replace('{', '').replace("['", "").replace('],', '\n')
        ])

        with open(today_expired_domains_carrier, "w") as file:
            file.write(results_today + "\n")
        logger.info("today_expired_domains_carrier file was created")

        with open(three_days_expired_domains_carrier, "w") as file:
            file.write(results_upcoming + "\n")
        logger.info("three_days_expired_domains_carrier file was created")

        response = webhook.send(text=results_today)
        assert response.status_code == 200
        assert response.body == "ok"

        response = webhook.send(text=results_upcoming)
        assert response.status_code == 200
        assert response.body == "ok"

        main()
        # new
        logger.info("collected domains data process- Done")
        move_old_file_to_arc(today_expired_domains_carrier, project_path_arc)
        # new
        logger.info("today expired domains file was moved to archive")

        move_old_file_to_arc(three_days_expired_domains_carrier, project_path_arc)
        # new
        logger.info("three days expired domains file was moved to archive")



# main with input
# if __name__ == '__main__':
    # logger.info('Starting the script')
    # parser = argparse.ArgumentParser(description='Run Carrier Whitelist')
    # parser.add_argument(dest='input_domain', help='input from slack')
    # args = parser.parse_args()
    # input = args.input_entity
    # main(input)

