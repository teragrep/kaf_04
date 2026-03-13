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
package com.teragrep.kaf_04.tests;

import com.teragrep.kaf_04.TeragrepKafkaAuthorizer;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.requests.RequestContext;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.network.KafkaAuthorizerServerInfo;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class TeragrepKafkaAuthorizerTests {

    private static TeragrepKafkaAuthorizer teragrepKafkaAuthorizer;

    @BeforeAll
    public static void testInstantiation() {
        teragrepKafkaAuthorizer = new TeragrepKafkaAuthorizer();
        HashMap<String, Object> configs = new HashMap<>();
        configs.put("teragrep.kaf_04.authorize.file", "src/test/resources/authorize.json");
        configs.put("teragrep.kaf_04.cluster.file", "src/test/resources/cluster.json");
        configs.put("teragrep.kaf_04.writer.file", "src/test/resources/writer.json");
        configs.put("teragrep.kaf_04.identitySuffix.file", "src/test/resources/identitySuffixEmpty.json");
        teragrepKafkaAuthorizer.configure(configs);
        teragrepKafkaAuthorizer
                .start(new KafkaAuthorizerServerInfo(null, 1, Collections.emptyList(), null, Collections.emptyList()));
    }

    @Test
    public void testConsumerOffsetRead() {
        RequestContext requestContext = createRequestContext("User", "root");
        ArrayList<Action> actions = createAction("Read", "__consumer_offsets");
        List<AuthorizationResult> results = teragrepKafkaAuthorizer.authorize(requestContext, actions);
        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals(AuthorizationResult.ALLOWED, results.get(0));
    }

    @Test
    public void testConsumerOffsetDescribe() {
        RequestContext requestContext = createRequestContext("User", "root");
        ArrayList<Action> actions = createAction("Describe", "__consumer_offsets");
        List<AuthorizationResult> results = teragrepKafkaAuthorizer.authorize(requestContext, actions);
        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals(AuthorizationResult.ALLOWED, results.get(0));

    }

    @Test
    public void testAuthorizedRead() {
        RequestContext requestContext = createRequestContext("User", "root");
        ArrayList<Action> actions = createAction("Read", "example_index");
        List<AuthorizationResult> results = teragrepKafkaAuthorizer.authorize(requestContext, actions);
        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals(AuthorizationResult.ALLOWED, results.get(0));

    }

    @Test
    public void testUnauthorizedRead() {
        RequestContext requestContext = createRequestContext("User", "example-user");
        ArrayList<Action> actions = createAction("Read", "example_index");
        List<AuthorizationResult> results = teragrepKafkaAuthorizer.authorize(requestContext, actions);
        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals(AuthorizationResult.DENIED, results.get(0));
    }

    @Test
    public void testAuthorizedWrite() {
        RequestContext requestContext = createRequestContext("User", "kafka-writer");
        ArrayList<Action> actions = createAction("Write", "example_index");
        List<AuthorizationResult> results = teragrepKafkaAuthorizer.authorize(requestContext, actions);
        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals(AuthorizationResult.ALLOWED, results.get(0));
    }

    @Test
    public void testUnauthorizedWrite() {
        RequestContext requestContext = createRequestContext("User", "example-user");
        ArrayList<Action> actions = createAction("Write", "example_index");
        List<AuthorizationResult> results = teragrepKafkaAuthorizer.authorize(requestContext, actions);
        Assertions.assertEquals(1, results.size());
        Assertions.assertEquals(AuthorizationResult.DENIED, results.get(0));
    }

    @AfterAll
    public static void closeAuthorizer() {
        teragrepKafkaAuthorizer.close();
    }

    private RequestContext createRequestContext(String type, String name) {
        return Assertions
                .assertDoesNotThrow(() -> new RequestContext(null, null, InetAddress.getByName("127.0.0.1"), new KafkaPrincipal(type, name), null, null, null, false));
    }

    private ArrayList<Action> createAction(String operation, String topic) {
        ArrayList<Action> actions = new ArrayList<>();
        actions
                .add(new Action(AclOperation.fromString(operation), new ResourcePattern(ResourceType.TOPIC, topic, PatternType.LITERAL), 0, false, false));
        return actions;
    }
}
