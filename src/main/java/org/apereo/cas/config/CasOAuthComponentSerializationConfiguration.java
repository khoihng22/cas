package org.apereo.cas.config;

import org.apereo.cas.ComponentSerializationPlan;
import org.apereo.cas.ComponentSerializationPlanConfigurator;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration("casOAuthComponentSerializationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class CasOAuthComponentSerializationConfiguration implements ComponentSerializationPlanConfigurator {
    
    @Override
    public void configureComponentSerializationPlan(final ComponentSerializationPlan plan) {
        plan.registerSerializableClass(OAuthAccessTokenExpirationPolicy.class);
        plan.registerSerializableClass(OAuthRefreshTokenExpirationPolicy.class);
        plan.registerSerializableClass(OAuthCodeExpirationPolicy.class);

        plan.registerSerializableClass(OAuthCodeImpl.class);
        plan.registerSerializableClass(AccessTokenImpl.class);
        plan.registerSerializableClass(RefreshTokenImpl.class);
    }
}
