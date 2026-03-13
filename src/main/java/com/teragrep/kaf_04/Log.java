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

import com.google.gson.JsonObject;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourcePattern;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;

public class Log {

    private final String hostname;

    public Log() {
        String hostname;
        try {
            hostname = InetAddress.getLocalHost().getHostName();
        }
        catch (UnknownHostException e) {
            hostname = "";
        }
        this.hostname = hostname;
    }

    public String authorization(
            final AuthorizableRequestContext authorizableRequestContext,
            final AclOperation operation,
            final ResourcePattern resourcePattern,
            final Boolean success,
            final String payload
    ) {
        String outcome = (success ? "OK" : "NOK");

        // request type_info
        JsonObject typeInfo = new JsonObject();
        typeInfo.addProperty("request_id", "");
        typeInfo.addProperty("session_id", getIp(authorizableRequestContext));
        typeInfo.addProperty("subject", authorizableRequestContext.principal().getName());
        typeInfo.addProperty("predicate", operation.name());
        typeInfo.addProperty("object", resourcePattern.resourceType() + "/" + resourcePattern.name());
        typeInfo.addProperty("outcome", outcome);

        // content
        JsonObject content = new JsonObject();
        if (payload != null) {
            content.addProperty("payload", payload);
        }

        // common info
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("timestamp", new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX").format(new Date()));
        jsonObject.addProperty("version", "1");
        jsonObject.addProperty("application", "teragrep");
        jsonObject.addProperty("environment", "");
        jsonObject.addProperty("component", "kaf_04");
        jsonObject.addProperty("instance", this.hostname);
        jsonObject.addProperty("retention", "");
        jsonObject.addProperty("uuid", UUID.randomUUID().toString());
        jsonObject.addProperty("type", "authorization");
        jsonObject.add("type_info", typeInfo);

        jsonObject.add("content", content);

        return jsonObject.toString();
    }

    private static String getIp(AuthorizableRequestContext authorizableRequestContext) {
        String ip = authorizableRequestContext.clientAddress().getHostAddress();

        // skip leading slash
        if (ip != null && !ip.isEmpty() && ip.charAt(0) == '/') {
            ip = ip.substring(1);
        }
        return ip;
    }
}
