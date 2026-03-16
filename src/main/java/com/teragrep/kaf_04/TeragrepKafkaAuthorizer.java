/*
 * Teragrep Authorization Module for Apache Kafka (kaf_04)
 * Copyright (C) 2019-2026 Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */
package com.teragrep.kaf_04;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.Uuid;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.metadata.authorizer.AclMutator;
import org.apache.kafka.metadata.authorizer.ClusterMetadataAuthorizer;
import org.apache.kafka.metadata.authorizer.StandardAcl;
import org.apache.kafka.server.authorizer.*;
import org.apache.kafka.common.acl.AclOperation;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TeragrepKafkaAuthorizer implements ClusterMetadataAuthorizer {

    // logging
    private static final Logger logger = LoggerFactory.getLogger(TeragrepKafkaAuthorizer.class);

    // Locations
    private String authorizePath;
    private String clusterPath;
    private String writerPath;
    private String identitySuffixPath;

    private ResourceOperationAuthorization resourceOperationAuthorization;

    private Boolean initialized = false;

    public TeragrepKafkaAuthorizer() {
    }

    @Override
    public void configure(Map<String, ?> configs) {
        this.authorizePath = getPath(
                configs, "teragrep.kaf_04.authorize.file", "/opt/teragrep/kaf_04/etc/authorize.json"
        );
        this.clusterPath = getPath(configs, "teragrep.kaf_04.cluster.file", "/opt/teragrep/kaf_04/etc/cluster.json");
        this.writerPath = getPath(configs, "teragrep.kaf_04.writer.file", "/opt/teragrep/kaf_04/etc/writer.json");
        this.identitySuffixPath = getPath(
                configs, "teragrep.kaf_04.identitySuffix.file", "/opt/teragrep/kaf_04/etc/identitySuffix.json"
        );
        logger.info("TeragrepKafkaAuthorizer configured.");
    }

    private String getPath(Map<String, ?> configs, String property, String fallback) {
        final Object config = configs.get(property);
        final String path;
        if (config instanceof String && !config.equals("")) {
            path = (String) config;
            logger.info("Resolved property <[{}]> to <[{}]>", property, path);
        }
        else {
            path = fallback;
            logger.info("Didn't find property <[{}]>, defaulting to <[{}]>", property, fallback);
        }
        return path;
    }

    @Override
    public void close() {
        logger.info("TeragrepKafkaAuthorizer closed.");
    }

    @Override
    public Map<Endpoint, ? extends CompletionStage<Void>> start(AuthorizerServerInfo authorizerServerInfo) {
        try {
            this.resourceOperationAuthorization = new ResourceOperationAuthorization(
                    authorizePath,
                    clusterPath,
                    writerPath,
                    identitySuffixPath
            );
            initialized = true;
            logger.info("TeragrepKafkaAuthorizer initialized.");
        }
        catch (FileNotFoundException e) {
            logger.warn("Failed to create Authorizer object: ", e);
        }
        return authorizerServerInfo
                .endpoints()
                .stream()
                .collect(Collectors.toMap(endpoint -> endpoint, endpoint -> CompletableFuture.completedFuture(null)));
    }

    @Override
    public List<AuthorizationResult> authorize(
            AuthorizableRequestContext authorizableRequestContext,
            List<Action> list
    ) {
        return list
                .stream()
                .map(action -> authorizeRequest(authorizableRequestContext, action))
                .collect(Collectors.toList());
    }

    private AuthorizationResult authorizeRequest(AuthorizableRequestContext authorizableRequestContext, Action action) {
        ResourceType resourceType = action.resourcePattern().resourceType();
        AclOperation aclOperation = action.operation();
        if (!initialized) {
            logger.warn("Authorizer is not yet initialized, refusing request");
            return AuthorizationResult.DENIED;
        }

        if (authorizableRequestContext.principal() == null) {
            logger.warn("Given principal is not set, refusing request");
            return AuthorizationResult.DENIED;
        }

        // We support only these resourcetypes
        if (
            !resourceType.equals(ResourceType.TOPIC) && !resourceType.equals(ResourceType.CLUSTER) && !resourceType
                    .equals(ResourceType.GROUP) && !resourceType.equals(ResourceType.TRANSACTIONAL_ID)
                    && !resourceType.equals(ResourceType.DELEGATION_TOKEN)
        ) {
            logger.warn("Unsupported resourceType={}", resourceType);
            return AuthorizationResult.DENIED;
        }

        // And only certain operations
        if (
            !aclOperation.equals(AclOperation.READ) && !aclOperation.equals(AclOperation.WRITE) && !aclOperation
                    .equals(AclOperation.ALTER) && !aclOperation.equals(AclOperation.DESCRIBE)
                    && !aclOperation.equals(AclOperation.CLUSTER_ACTION) && !aclOperation.equals(AclOperation.CREATE) && !aclOperation.equals(AclOperation.DELETE) && !aclOperation.equals(AclOperation.DESCRIBE_CONFIGS) && !aclOperation.equals(AclOperation.ALTER_CONFIGS) && !aclOperation.equals(AclOperation.IDEMPOTENT_WRITE)
        ) {
            logger
                    .warn(
                            "Unsupported access type. session={}, operation={}, resource={}",
                            authorizableRequestContext, aclOperation, resourceType
                    );
            return AuthorizationResult.DENIED;
        }

        try {
            return resourceOperationAuthorization
                    .authorize(authorizableRequestContext, aclOperation, action.resourcePattern());
        }
        catch (IOException e) {
            logger.warn("Failure with getting authorization information: " + e);
            return AuthorizationResult.DENIED;
        }
    }

    @Override
    public void setAclMutator(AclMutator aclMutator) {
        logger.debug("setAclMutator(AclMutator aclMutator) is not used by TeragrepKafkaAuthorizer");
    }

    @Override
    public AclMutator aclMutatorOrException() {
        logger.warn("aclMutatorOrException() is not supported by TeragrepKafkaAuthorizer");
        return null;
    }

    @Override
    public void completeInitialLoad() {
        logger.debug("completeInitialLoad() is not used by TeragrepKafkaAuthorizer");
    }

    @Override
    public void completeInitialLoad(Exception e) {
        logger.warn("completeInitialLoad(Exception e) is not supported by TeragrepKafkaAuthorizer");
    }

    @Override
    public void loadSnapshot(Map<Uuid, StandardAcl> map) {
        logger.debug("loadSnapshot(Map<Uuid, StandardAcl> map) is not used by TeragrepKafkaAuthorizer");
    }

    @Override
    public void addAcl(Uuid uuid, StandardAcl standardAcl) {
        logger.warn("addAcl(Uuid uuid, StandardAcl standardAcl) is not supported by TeragrepKafkaAuthorizer");
    }

    @Override
    public void removeAcl(Uuid uuid) {
        logger.warn("removeAcl(Uuid uuid) is not supported by TeragrepKafkaAuthorizer");
    }

    @Override
    public List<? extends CompletionStage<AclCreateResult>> createAcls(
            AuthorizableRequestContext authorizableRequestContext,
            List<AclBinding> list
    ) {
        logger.warn("addAcls(Set<Acl>, Resource) is not supported by TeragrepKafkaAuthorizer");
        return null;
    }

    @Override
    public List<? extends CompletionStage<AclDeleteResult>> deleteAcls(
            AuthorizableRequestContext authorizableRequestContext,
            List<AclBindingFilter> list
    ) {
        logger.warn("addAcls(Set<Acl>, Resource) is not supported by TeragrepKafkaAuthorizer");
        return null;
    }

    @Override
    public Iterable<AclBinding> acls(AclBindingFilter aclBindingFilter) {
        logger.warn("acls(AclBindingFilter aclBindingFilter) is not supported by TeragrepKafkaAuthorizer");
        return null;
    }
}
