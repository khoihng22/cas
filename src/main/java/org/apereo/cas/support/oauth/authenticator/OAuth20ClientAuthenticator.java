package org.apereo.cas.support.oauth.authenticator;

import org.apereo.cas.audit.AuditableContext;
import org.apereo.cas.audit.AuditableExecution;
import org.apereo.cas.audit.AuditableExecutionResult;
import org.apereo.cas.authentication.principal.ServiceFactory;
import org.apereo.cas.authentication.principal.WebApplicationService;
import org.apereo.cas.services.ServicesManager;
import org.apereo.cas.support.oauth.services.OAuthRegisteredService;
import org.apereo.cas.support.oauth.util.OAuth20Utils;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.credentials.authenticator.Authenticator;
import org.pac4j.core.exception.CredentialsException;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authenticator for client credentials authentication.
 *
 * @author Jerome Leleu
 * @since 5.0.0
 */
public class OAuth20ClientAuthenticator implements Authenticator<UsernamePasswordCredentials> {
	
	static Logger LOGGER = LoggerFactory.getLogger(OAuth20CasAuthenticationBuilder.class);
	
    private final ServicesManager servicesManager;
    private final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory;
    private final AuditableExecution registeredServiceAccessStrategyEnforcer;

    public OAuth20ClientAuthenticator(ServicesManager servicesManager,
			ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory,
			AuditableExecution registeredServiceAccessStrategyEnforcer) {
		super();
		this.servicesManager = servicesManager;
		this.webApplicationServiceServiceFactory = webApplicationServiceServiceFactory;
		this.registeredServiceAccessStrategyEnforcer = registeredServiceAccessStrategyEnforcer;
	}

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
