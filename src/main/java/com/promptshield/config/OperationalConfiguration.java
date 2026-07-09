package com.promptshield.config;

import com.promptshield.observability.CorrelationIdFilter;
import com.promptshield.observability.ScanMetrics;
import com.promptshield.observability.ScanMetricsMeterBinder;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/** Wires request correlation and privacy-safe scan metrics. */
@Configuration(proxyBeanMethods = false)
public class OperationalConfiguration {

    @Bean
    ScanMetrics scanMetrics() {
        return new ScanMetrics();
    }

    @Bean
    MeterBinder scanMetricsMeterBinder(ScanMetrics scanMetrics) {
        return new ScanMetricsMeterBinder(scanMetrics);
    }

    @Bean
    FilterRegistrationBean<CorrelationIdFilter> correlationIdFilterRegistration() {
        FilterRegistrationBean<CorrelationIdFilter> registration = new FilterRegistrationBean<>(new CorrelationIdFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }

}
