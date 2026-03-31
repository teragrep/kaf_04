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

import com.google.gson.Gson;
import com.teragrep.jai_01.IAuthorizationInfoProcessor;
import com.teragrep.jai_01.ReloadingAuthorizationInfoProcessor;
import com.teragrep.jue_01.UnixGroupSearch;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashSet;

public final class ResourceOperationAuthorization {

    private static final Logger logger = LoggerFactory.getLogger(ResourceOperationAuthorization.class);

    private final IAuthorizationInfoProcessor authorizationInfoProcessor;
    private final UnixGroupSearch unixGroupSearch;

    private final Username clusterUsername;
    private final Username writerUsername;
    private final String identitySuffix;
    private final Log logRenderer;

    public ResourceOperationAuthorization(
            String authorizePath,
            String clusterPath,
            String writerPath,
            String identitySuffixPath
    ) throws IOException {
        final Gson gson = new Gson();
        this.logRenderer = new Log();
        this.authorizationInfoProcessor = new ReloadingAuthorizationInfoProcessor(authorizePath, 300);

        final BufferedReader clusterUsernameReader = Files
                .newBufferedReader(Paths.get(clusterPath), StandardCharsets.UTF_8);
        this.clusterUsername = gson.fromJson(clusterUsernameReader, Username.class);

        final BufferedReader writerUsernameReader = Files
                .newBufferedReader(Paths.get(writerPath), StandardCharsets.UTF_8);
        this.writerUsername = gson.fromJson(writerUsernameReader, Username.class);

        String identitySuffixString = "";
        try {
            final BufferedReader identitySuffixReader = Files
                    .newBufferedReader(Paths.get(identitySuffixPath), StandardCharsets.UTF_8);
            IdentitySuffix identitySuffixObj = gson.fromJson(identitySuffixReader, IdentitySuffix.class);
            identitySuffixString = identitySuffixObj.identitySuffix;
        }
        catch (FileNotFoundException ignored) {

        }
        this.identitySuffix = identitySuffixString;

        this.unixGroupSearch = new UnixGroupSearch();

    }

    public AuthorizationResult authorize(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) throws IOException {
        final String userName = authorizableRequestContext.principal().getName();
        if ("ANONYMOUS".equalsIgnoreCase(userName)) {
            logger
                    .info(
                            logRenderer
                                    .authorization(
                                            authorizableRequestContext, operation, resourcePattern, true,
                                            "kaf_04 does not support authorizing username " + "<[" + userName + "]>"
                                    )
                    );
            return AuthorizationResult.DENIED;
        }

        if (isClusterUser(authorizableRequestContext, operation, resourcePattern, userName)) {
            logger.debug(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, true, null));
            return AuthorizationResult.ALLOWED;
        }
        if (isTopicWriteUser(authorizableRequestContext, operation, resourcePattern, userName)) {
            logger.debug(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, true, null));
            return AuthorizationResult.ALLOWED;
        }
        if (isGroupDescribe(authorizableRequestContext, operation, resourcePattern)) { // readers need
            // group describes are logged always
            logger.info(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, true, null));
            return AuthorizationResult.ALLOWED;
        }
        if (isGroupRead(authorizableRequestContext, operation, resourcePattern)) { // readers need
            // group reads are logged always
            logger.info(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, true, null));
            return AuthorizationResult.ALLOWED;
        }
        if (
            isTopicRead__consumer_offsets(authorizableRequestContext, operation, resourcePattern)
                    || isTopicDescribe__consumer_offsets(authorizableRequestContext, operation, resourcePattern)
        ) {
            // consumer offsets reads and describes are logged always
            logger.info(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, true, null));
            return AuthorizationResult.ALLOWED;
        }

        if (
            isTopicRead(authorizableRequestContext, operation, resourcePattern)
                    || isTopicDescribe(authorizableRequestContext, operation, resourcePattern)
        ) {
            final java.util.HashSet<String> origIdentityMemberOfSet = unixGroupSearch
                    .getGroups(userName + identitySuffix);
            final HashSet<String> identityMemberOfSet = new HashSet<>(origIdentityMemberOfSet);
            final String index = resourcePattern.name(); // topic
            final HashSet<String> indexesGroupSet = authorizationInfoProcessor.getGroupsForIndex(index);
            identityMemberOfSet.retainAll(indexesGroupSet);

            if (identityMemberOfSet.isEmpty()) {
                String payload = "Access to: [" + index + "] denied for " + "identity [" + userName + identitySuffix
                        + "] who is member of groups <" + origIdentityMemberOfSet
                        + "> but allowed groups for indexes <[" + index + "]> are: <" + indexesGroupSet + ">";
                logger
                        .info(
                                logRenderer
                                        .authorization(
                                                authorizableRequestContext, operation, resourcePattern, false, payload
                                        )
                        );
                return AuthorizationResult.DENIED;
            }
            // topic reads are logged always
            logger.info(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, true, null));
            return AuthorizationResult.ALLOWED;
        }
        // rejected are logged always
        logger.info(logRenderer.authorization(authorizableRequestContext, operation, resourcePattern, false, null));
        return AuthorizationResult.DENIED;
    }

    private boolean isClusterUser(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern,
            final String userName
    ) {
        return userName.equals(clusterUsername.username)
                // CLUSTER resource permissions
                && (((AclOperation.ALTER.equals(operation) || AclOperation.ALTER_CONFIGS.equals(operation) || AclOperation.CLUSTER_ACTION.equals(operation) || AclOperation.CREATE.equals(operation) || AclOperation.DESCRIBE.equals(operation) || AclOperation.DESCRIBE_CONFIGS.equals(operation) || AclOperation.IDEMPOTENT_WRITE.equals(operation)) && ResourceType.CLUSTER.equals(resourcePattern.resourceType())) ||
                // TOPIC resource permissions
                        ((AclOperation.DESCRIBE.equals(operation) || AclOperation.CREATE.equals(operation)
                                || AclOperation.ALTER.equals(operation) || AclOperation.DELETE.equals(operation))
                                && ResourceType.TOPIC.equals(resourcePattern.resourceType())));
    }

    private boolean isTopicWriteUser(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern,
            final String userName
    ) {
        return userName.equals(writerUsername.username) && (AclOperation.WRITE.equals(operation)
                || AclOperation.DESCRIBE.equals(operation) || AclOperation.CREATE.equals(operation))
                && ResourceType.TOPIC.equals(resourcePattern.resourceType());
    }

    private boolean isGroupDescribe(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) {
        return AclOperation.DESCRIBE.equals(operation) && ResourceType.GROUP.equals(resourcePattern.resourceType());
    }

    private boolean isGroupRead(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) {
        return AclOperation.READ.equals(operation) && ResourceType.GROUP.equals(resourcePattern.resourceType());
    }

    private boolean isTopicRead(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) {
        return AclOperation.READ.equals(operation) && ResourceType.TOPIC.equals(resourcePattern.resourceType());
    }

    private boolean isTopicDescribe(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) {
        return AclOperation.DESCRIBE.equals(operation) && ResourceType.TOPIC.equals(resourcePattern.resourceType());
    }

    private boolean isTopicRead__consumer_offsets(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) {
        return AclOperation.READ.equals(operation) && ResourceType.TOPIC.equals(resourcePattern.resourceType())
                && "__consumer_offsets".equals(resourcePattern.name());
    }

    private boolean isTopicDescribe__consumer_offsets(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern
    ) {
        return AclOperation.DESCRIBE.equals(operation) && ResourceType.TOPIC.equals(resourcePattern.resourceType())
                && "__consumer_offsets".equals(resourcePattern.name());
    }
}
