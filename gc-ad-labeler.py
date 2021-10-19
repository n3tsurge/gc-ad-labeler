import time
import logging
from argparse import ArgumentParser
from pyaml_env import parse_config
from guardicore.centra import CentraAPI
from ldap3 import Server, Connection, SAFE_SYNC, ALL_ATTRIBUTES, SUBTREE


def load_config(path: str = "config.yml") -> dict:
    """Loads the configuration file for the application
    and returns a configuration object for consumption in
    other areas

    Parameters:
        path (str): The path on the file system to load the config file

    Returns:
        dict: A dictionary of configuration values
    """
    config_error = False
    config = parse_config(path)

    return config


def get_computers(server_name: str, username: str, password: str, base_dn: str, target_dn: str) -> list:
    """
    Loads computers from an LDAP group or Active Directory OU in to a list
    that can be processed by another function.

    Parameters:
        server_name (str): The server to bind to
        base_dn (str): The base DN of the domain
        username (str): The DN of the user used to bind to ldap
        password (str): The password of the user to bind to ldap
        target_dn (str): The distinguished name of the target OU or Group
    
    Returns:
        list: The list of computers in the OU or AD group
    """

    search_filter = "(objectclass=computer)" # The default search filter
    result = [] # Empty result set

    # If looking for group members
    if target_dn.startswith('CN'):
        search_filter = f"(&(objectClass=computer)(memberof={target_dn}))"
    else:
        base_dn = target_dn
    
    # If the secure ports are defined on the server name
    # establish the connection over TLS/SSL
    if any([server_name.endswith('636'),server_name.endswith('3269')]):
        server = Server(server_name.split(':')[0], use_ssl=True)
    else:
        server = Server(server_name)

    connection = Connection(server, username, password, client_strategy=SAFE_SYNC, auto_bind=True)

    # Gets all the computer objects in a specified OU and returns
    # a list of computer names
    generator = connection.extend.standard.paged_search(
        base_dn, search_filter, attributes=['name'], paged_size=250, generator=True
    )

    # Only return results that have attributes
    result = [computer['attributes']['name'] for computer in generator if 'attributes' in computer]
    return result


if __name__ == "__main__":
    # Set the logging format
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    parser = ArgumentParser()
    parser.add_argument('--config', help="The path to the configuration file", default="config.yml", required=False)
    parser.add_argument('--gc-management-url', help="Guardicore management URL", required=False)
    parser.add_argument('-u', '--user', help="Guardicore username", required=False)
    parser.add_argument('-p', '--password', help="Prompt for the Guardicore password", required=False, action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.user:
        config['guardicore']['username'] = args.user

    if args.password:
        config['guardicore']['password'] = getpass(prompt="Password: ")

    if args.gc_management_url:
        config['guardicore']['management_url'] = args.gc_management_url

    logging.info("Authenticating to Guardicore")
    centra = CentraAPI(management_url=config['guardicore']['management_url'])

    try:
        centra.authenticate(
            username=config['guardicore']['username'], password=config['guardicore']['password'])
    except Exception as exc:
        logging.error(exc)
        exit(1)

    while True:
        for rule in config['rules']:
            rule_config = config['rules'][rule]
            domain_config = config['domains'][rule_config['domain']]

            logging.info(f'Fetching computers for {rule}')
            computers = get_computers(
                server_name=domain_config['server'],
                base_dn=domain_config['base_dn'],
                username=domain_config['bind_user'],
                password=domain_config['bind_password'],
                target_dn=rule_config['target_dn']
            )

            guardicore_agent_ids = []

            for computer in computers:
                agent_info = centra.list_agents(gc_filter=computer)
                if len(agent_info) > 0:
                    guardicore_agent_ids.append(agent_info[0]['asset_id'])

            number_of_agents = len(guardicore_agent_ids)

            for key in rule_config['labels']:

                changed=False
                value = rule_config['labels'][key]

                label_data = centra.list_labels(key=key, value=value, find_matches=True)
                if len(label_data) > 0:
                    new_agents = [a for a in guardicore_agent_ids if a not in [b['id'] for b in label_data[0]['added_assets']]]

                    # Determine what agents are no longer valid
                    old_agents = [b['id'] for b in label_data[0]['added_assets'] if b['id'] not in guardicore_agent_ids]

                    if len(old_agents) > 0:
                        if centra.remove_asset_from_label(key, value, old_agents):
                            logging.info(f"Removed {len(old_agents)} from label {key}: {value}")
                    
                    if len(new_agents) > 0:
                        centra.create_static_label(key, value, new_agents)
                        logging.info(f"Labeled {len(new_agents)} with label {key}: {value}")
                        changed=True

                    if not changed:
                        logging.info(f"No changes for {key}: {value}")
                else:
                    logging.info(f"Labeled {number_of_agents} with {key}: {value}")
                    centra.create_static_label(key, value, guardicore_agent_ids)

        time.sleep(config['poll_interval'])
