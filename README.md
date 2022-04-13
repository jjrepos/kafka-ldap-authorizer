# kafka-ldap-authorizer plugin

Kafka LDAP Authentication and Authorization Plugin

Step1: Create the LDAP Security Groups
|LDAP Group          | Purpose                  |
| :-----------------:|:------------------------:|
| KAFKA-ADMIN_GRP    |     Kafka Admins         |
| KAFKA-SUPERUSER_GRP| Kafka Super User (Topics CRUD, Groups CRUD, Partitions, Read cluster config) |
| KAFKA-READ_GRP     | Read Topics              |
| KAFKA-WRITE_GRP    | Write Topics             |

Step2: Create an LDAP service account for server side auth and replace the server.settings properties below.

Step 3: Change kafka server.properties
############################# Security Settings ###############################################
sasl.enabled.mechanisms=PLAIN
sasl.mechanism.inter.broker.protocol=PLAIN
security.inter.broker.protocol=SASL_PLAINTEXT
listener.name.sasl_plaintext.plain.sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required \
username="<kafka_broker_username>" \
password="<password_to_kafka_broker>";
listener.name.sasl_plaintext.plain.sasl.server.callback.handler.class=com.jjrepos.kafka.security.ldap.authenticator.LdapAuthenticateCallbackHandler
################################ Authorization ###################################################
authorizer.class.name=com.jjrepos.kafka.security.ldap.authorizer.LdapAuthorizer


Step 4: All clients need to create a service account and associate them with one of the security groups above for access  to the cluster    

