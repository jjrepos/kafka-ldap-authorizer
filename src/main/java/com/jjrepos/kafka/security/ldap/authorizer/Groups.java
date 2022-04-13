package com.jjrepos.kafka.security.ldap.authorizer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public enum Groups {
    READ("KAFKA-READ_GRP", Arrays.asList(
            new GroupAction(ResourceType.TOPIC, AclOperation.DESCRIBE),
            new GroupAction(ResourceType.TOPIC, AclOperation.READ),
            new GroupAction(ResourceType.GROUP, AclOperation.ALL))),

    WRITE("KAFKA-WRITE_GRP", Arrays.asList(
            new GroupAction(ResourceType.TOPIC, AclOperation.DESCRIBE),
            new GroupAction(ResourceType.TOPIC, AclOperation.WRITE),
            new GroupAction(ResourceType.TOPIC, AclOperation.IDEMPOTENT_WRITE),
            new GroupAction(ResourceType.TRANSACTIONAL_ID, AclOperation.DESCRIBE),
            new GroupAction(ResourceType.TRANSACTIONAL_ID, AclOperation.WRITE),
            new GroupAction(ResourceType.CLUSTER, AclOperation.IDEMPOTENT_WRITE))),

    ADMIN("KAFKA-ADMIN_GRP", Collections.singletonList(
            new GroupAction(ResourceType.ANY, AclOperation.ALL))),

    SUPER_USER("KAFKA-SUPERUSER_GRP",
            Arrays.asList(
                    new GroupAction(ResourceType.CLUSTER, AclOperation.DESCRIBE),
                    new GroupAction(ResourceType.CLUSTER, AclOperation.DESCRIBE_CONFIGS),
                    new GroupAction(ResourceType.TOPIC, AclOperation.ALL),
                    new GroupAction(ResourceType.GROUP, AclOperation.ALL),
                    new GroupAction(ResourceType.TRANSACTIONAL_ID, AclOperation.ALL),
                    new GroupAction(ResourceType.CLUSTER, AclOperation.IDEMPOTENT_WRITE)));


    public final String name;
    public final List<GroupAction> groupActions;


    Groups(String name, List<GroupAction> groupActions) {
        this.name = name;
        this.groupActions = groupActions;
    }

    /**
     * Gets a {@link Groups} for a LDAP group name.
     * This method when no matching Enum is found, does not throw an exception,
     * because a typical BAH service account, has more groups than required kafka groups.
     *
     * @param name LDAP group name such as "KAFKA-READ_GRP"
     * @return {@link Groups} if present, null otherwise
     */
    public static Groups valueOfName(String name) {
        return Arrays.stream(values())
                .filter(value -> value.name.equals(name))
                .findFirst()
                .orElse(null);
    }

    @Override
    public String toString() {
        return this.name;
    }


}
