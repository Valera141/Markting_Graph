package com.example.Marketing.configuration;

import graphql.GraphQLError;
import graphql.schema.DataFetchingEnvironment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.graphql.execution.DataFetcherExceptionResolverAdapter;
import org.springframework.graphql.execution.ErrorType;
import org.springframework.lang.NonNull; // <-- 1. IMPORTA ESTO
import org.springframework.validation.BindException;

@Configuration
public class GraphqlConfig {

    @Bean
    public DataFetcherExceptionResolverAdapter validationExceptionResolver() {
        return new DataFetcherExceptionResolverAdapter() {
            @Override
            protected GraphQLError resolveToSingleError(@NonNull Throwable ex, @NonNull DataFetchingEnvironment env) { // <-- 2. AÑADE @NonNull AQUÍ
                if (ex instanceof BindException bindException) {
                    
                    String message = bindException.getBindingResult().getAllErrors().get(0).getDefaultMessage();

                    return GraphQLError.newError()
                            .errorType(ErrorType.BAD_REQUEST)
                            .message(message)
                            .path(env.getExecutionStepInfo().getPath())
                            .location(env.getField().getSourceLocation())
                            .build();
                }
                return null;
            }
        };
    }
}