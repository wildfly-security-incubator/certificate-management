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
import org.wildfly.security.certificate.management.x500.cert.spi.HttpClientSpi;
import org.wildfly.security.certificate.management.x500.cert.spi.HttpRequestSpi;
import org.wildfly.security.certificate.management.x500.cert.spi.HttpResponseSpi;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;

@MetaInfServices(value = HttpClientSpi.class)
public class HttpClientSpiImpl implements HttpClientSpi {

    HttpClient httpClient = HttpClient.newHttpClient();

    @Override
    public Future<HttpResponseSpi> sendAsyncRequest(HttpRequestSpi httpRequest) {

        Map<String, List<String>> headers = httpRequest.getHeaders();
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .method(httpRequest.getMethod(), HttpRequest.BodyPublishers.noBody())
                .uri(httpRequest.getURI());

        headers.forEach((headerKey, headerValues) -> headerValues.forEach(value -> builder.header(headerKey, value)));
        HttpRequest builtHttpRequest = builder.build();
        CompletableFuture<HttpResponse<String>> httpResponse = this.httpClient.sendAsync(builtHttpRequest, HttpResponse.BodyHandlers.ofString());
        return httpResponse.thenApply((stringHttpResponse) -> {
            return new HttpResponseSpi() {
                @Override
                public String body() {
                    return stringHttpResponse.body();
                }

                @Override
                public Map<String, List<String>> getHeaders() {
                    return stringHttpResponse.headers().map();
                }

                @Override
                public List<String> getHeaderValues(String key) {
                    return stringHttpResponse.headers().allValues(key);
                }

                @Override
                public int statusCode() {
                    return stringHttpResponse.statusCode();
                }

                @Override
                public URI uri() {
                    return stringHttpResponse.uri();
                }

                @Override
                public HttpRequestSpi request() {
                    return null;
                }
            };
        });
    }
}
