/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2024 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.security.certificate.management.x500.cert.acme;

import org.kohsuke.MetaInfServices;
import org.wildfly.security.certificate.management.x500.cert.spi.HttpRequestSpi;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@MetaInfServices(value = HttpRequestSpi.class)
public class HttpRequestSpiImpl implements HttpRequestSpi {

    String method;
    URI uri;
    Map<String, List<String>> headers = new HashMap<>();
    String body;
    HttpRequest httpRequest;


    @Override
    public void setMethod(String method) {
        this.method = method;
    }

    @Override
    public void setURI(URI uri) {
        this.uri = uri;
    }

    @Override
    public void setHeaders(Map<String, List<String>> headers) {
        this.headers = headers;
    }

    @Override
    public void setHeader(String key, List<String> value) {
        this.headers.put(key, value);
    }

    @Override
    public void setBody(String body) {
        this.body = body;
    }

    @Override
    public String getMethod() {
        return this.method;
    }

    @Override
    public URI getURI() {
        return this.uri;
    }

    @Override
    public Map<String, List<String>> getHeaders() {
        return this.headers;
    }

    @Override
    public List<String> getHeader(String key) {
        return this.headers.get(key);
    }

    @Override
    public String getBody() {
        return this.body;
    }
}
