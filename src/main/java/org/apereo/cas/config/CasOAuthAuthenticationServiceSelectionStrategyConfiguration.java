package org.apereo.cas.config;

import org.apereo.cas.authentication.AuthenticationServiceSelectionPlan;
import org.apereo.cas.authentication.AuthenticationServiceSelectionStrategy;
import org.apereo.cas.authentication.AuthenticationServiceSelectionStrategyConfigurer;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration("casOAuthAuthenticationServiceSelectionStrategyConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CasOAuthAuthenticationServiceSelectionStrategyConfiguration implements AuthenticationServiceSelectionStrategyConfigurer {
    
    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;

    @Autowired
    @Qualifier("webApplicationServiceFactory")
    private ServiceFactory<WebApplicationService> webApplicationServiceFactory;

    @Bean
    @ConditionalOnMissingBean(name = "oauth20AuthenticationRequestServiceSelectionStrategy")
    @RefreshScope
    public AuthenticationServiceSelectionStrategy oauth20AuthenticationRequestServiceSelectionStrategy() {
        return new OAuth20AuthenticationServiceSelectionStrategy(servicesManager,
                webApplicationServiceFactory, OAuth20Utils.casOAuthCallbackUrl(casProperties.getServer().getPrefix()));
    }
    
    @Override
    public void configureAuthenticationServiceSelectionStrategy(final AuthenticationServiceSelectionPlan plan) {
        plan.registerStrategy(oauth20AuthenticationRequestServiceSelectionStrategy());
    }
}

