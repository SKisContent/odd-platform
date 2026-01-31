package org.opendatadiscovery.oddplatform.auth.filter;

import org.opendatadiscovery.oddplatform.auth.session.SessionConstants;
import org.opendatadiscovery.oddplatform.repository.reactive.ReactiveCollectorRepository;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Component
public class IngestionDataSourceFilter extends AbstractIngestionFilter {
    private final ReactiveCollectorRepository collectorRepository;

    public IngestionDataSourceFilter(final ReactiveCollectorRepository collectorRepository) {
        super(new PathPatternParserServerWebExchangeMatcher("/ingestion/datasources", HttpMethod.POST));
        this.collectorRepository = collectorRepository;
    }

    @Override
    protected ServerHttpRequestDecorator getRequestDecorator(final ServerWebExchange exchange) {
        return new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return super.getBody().collectList()
                    .flatMapMany(dataBuffer -> {
                        try {
                            final String token = resolveToken(exchange.getRequest());
                            return collectorRepository.getByToken(token)
                                .zipWith(exchange.getSession())
                                .doOnNext(t -> t.getT2().getAttributes()
                                    .put(SessionConstants.COLLECTOR_ID_SESSION_KEY, t.getT1().getId()))
                                .thenMany(Flux.fromIterable(dataBuffer))
                                .switchIfEmpty(Flux.fromIterable(dataBuffer));
                        } catch (Exception e) {
                            // Token is missing or invalid - proceed without authentication
                            return Flux.fromIterable(dataBuffer);
                        }
                    });
            }
        };
    }
}
