package org.apereo.cas.support.oauth.authenticator;

import org.apache.http.auth.UsernamePasswordCredentials;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.ServicesManager;

@AllArgsConstructor
public class OAuth20ClientAuthenticator implements Authenticator<UsernamePasswordCredentials> {
    private final ServicesManager servicesManager;
    private final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory;
    private final AuditableExecution registeredServiceAccessStrategyEnforcer;

    @Override
    public void validate(final UsernamePasswordCredentials credentials, final WebContext context) throws CredentialsException {
        LOGGER.debug("Authenticating credential [{}]", credentials);

        final String id = credentials.getUsername();
        final String secret = credentials.getPassword();
        
        final OAuthRegisteredService registeredService = OAuth20Utils.getRegisteredOAuthServiceByClientId(this.servicesManager, id);
        if (registeredService == null) {
            throw new CredentialsException("Unable to locate registered service for " + id);
        }

        final AuditableContext audit = AuditableContext.builder()
            .service(this.webApplicationServiceServiceFactory.createService(registeredService.getServiceId()))
            .registeredService(registeredService)
            .build();
        final AuditableExecutionResult accessResult = this.registeredServiceAccessStrategyEnforcer.execute(audit);
        accessResult.throwExceptionIfNeeded();

        if (!OAuth20Utils.checkClientSecret(registeredService, secret)) {
            throw new CredentialsException("Bad secret for client identifier: " + id);
        }

        final CommonProfile profile = new CommonProfile();
        profile.setId(id);
        credentials.setUserProfile(profile);
        LOGGER.debug("Authenticated user profile [{}]", profile);
    }
}

