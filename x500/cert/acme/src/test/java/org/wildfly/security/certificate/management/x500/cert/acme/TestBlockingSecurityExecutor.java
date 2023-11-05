/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2023 Red Hat, Inc., and individual contributors
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

import io.smallrye.mutiny.Uni;
import io.smallrye.mutiny.subscription.UniEmitter;

import java.util.concurrent.Executor;
import java.util.function.Consumer;
import java.util.function.Supplier;

public interface TestBlockingSecurityExecutor {
    <T> Uni<T> executeBlocking(Supplier<? extends T> supplier);

    static TestBlockingSecurityExecutor createTestBlockingExecutor(Supplier<Executor> executorSupplier) {
        return new TestBlockingSecurityExecutor() {
            @Override
            public <T> Uni<T> executeBlocking(Supplier<? extends T> function) {
                return Uni.createFrom().deferred(new Supplier<Uni<? extends T>>() {
                    @Override
                    public Uni<? extends T> get() {
                        return Uni.createFrom().emitter(new Consumer<UniEmitter<? super T>>() {
                            @Override
                            public void accept(UniEmitter<? super T> uniEmitter) {
                                executorSupplier.get().execute(new Runnable() {
                                    @Override
                                    public void run() {
                                        try {
                                            uniEmitter.complete(function.get());
                                        } catch (Throwable t) {
                                            uniEmitter.fail(t);
                                        }
                                    }
                                });
                            }
                        });
                    }
                });
            }
        };
    }
}
