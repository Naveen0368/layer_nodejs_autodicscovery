import sys
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, AUTO_BIND_NO_TLS, SUBTREE
from ldap3.core.exceptions import LDAPCursorError
import pprint

server_name = '10.128.7.80'
domain_name = 'ul.com'
user_name = 'Administrator'
password = 'aEDq:c7y'

def get_all_ad_hosts(connection):
    results=[]
    elements = connection.extend.standard.paged_search(
        search_base='DC=ul,DC=com',
        # search_filter='(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
        search_filter='(&(objectCategory=computer))',
        search_scope=SUBTREE,
        attributes='*',
        paged_size=100)
    printed=False
    for element in elements:
        host = dict()
        if 'dn' in element:
            if not printed:
                # print(element['attributes'])
                pprint.pprint(element['attributes'])
                printed = True
                print('#' * 24)
            # for each in element['attributes']:
            #     print(each)

        # if 'dn' in element:
        #     print (element['attributes'])
        #     # host['dn'] = element['dn']
        #     # host['name'] = element['attributes'][u'name'][0]
        #     # host['memberOf'] = element['attributes'][u'memberOf']
        #     # print(host)
        #     results.append(host)
    # print(results)
    return(results)

# format_string = '{:25} {:>6} {:19} {:19} {}'
# print(format_string.format('User', 'Logins', 'Last Login', 'Expires', 'Description'))

server = Server(server_name, get_info=ALL)
conn = Connection(server, user='{}\\{}'.format(domain_name, user_name), password=password, authentication=NTLM, auto_bind=True,auto_referrals=False)

get_all_ad_hosts(conn)

