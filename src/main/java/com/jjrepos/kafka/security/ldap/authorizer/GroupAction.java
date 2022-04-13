package com.jjrepos.kafka.security.ldap.authorizer;

import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;

import java.util.StringJoiner;

public class GroupAction {
    private final ResourceType resourceType;
    private final AclOperation operation;

    public GroupAction(ResourceType resourceType, AclOperation operation) {
        this.resourceType = resourceType;
        this.operation = operation;
    }

    public ResourceType resourceType() {
        return resourceType;
    }

    public AclOperation operation() {
        return operation;
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", GroupAction.class.getSimpleName() + "[", "]")
                .add("resourceType=" + resourceType)
                .add("operation=" + operation)
                .toString();
    }
}
