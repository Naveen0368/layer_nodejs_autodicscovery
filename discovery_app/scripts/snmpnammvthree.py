from easysnmp import Session


# session3 = Session(hostname='10.128.7.175', version=3,
# security_level="auth_with_privacy", security_username="uladminV3",
# auth_protocol="MD5", auth_password="aEDq:c7y",
# privacy_protocol="AES", privacy_password="aEDq:c7y")


session3 = Session(hostname='10.128.7.95', version=3,
security_level="auth_with_privacy", security_username="uladminv3",
auth_protocol="SHA", auth_password="aEDq:c7y",
privacy_protocol="AES",privacy_password="aEDq:c7y")

print(session3.walk('iso.3.6.1.2.1.1.1')[0].value)


# session32 = Session(hostname='10.128.7.176', version=3,
# security_level="auth_without_privacy", security_username="uladminv3",
# auth_protocol="SHA", auth_password="aEDq:c7y",
# privacy_protocol="AES")
#
# print(session32.walk('iso.3.6.1.2.1.1.1')[0].value)

# security_level = auth_with_privacy,auth_without_privacy,auth_with_privacy
# auth_protocol = MD5, SHA
# privacy_protocol = AES, DES, 3DES
