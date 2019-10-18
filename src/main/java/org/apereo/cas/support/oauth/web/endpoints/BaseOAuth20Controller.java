package org.apereo.cas.support.oauth.web.endpoints;

@Controller
@Slf4j
@AllArgsConstructor
public abstract class BaseOAuth20Controller {

    /**
     * Services manager.
     */
    protected final ServicesManager servicesManager;

    /**
     * The Ticket registry.
     */
    protected final TicketRegistry ticketRegistry;

    /**
     * The Access token factory.
     */
    protected final AccessTokenFactory accessTokenFactory;

    /**
     * The Principal factory.
     */
    protected final PrincipalFactory principalFactory;

    /**
     * The Web application service service factory.
     */
    protected final ServiceFactory<WebApplicationService> webApplicationServiceServiceFactory;

    /**
     * Convert profile scopes to attributes.
     */
    protected final OAuth20ProfileScopeToAttributesFilter scopeToAttributesFilter;

    /**
     * Collection of CAS settings.
     */
    protected final CasConfigurationProperties casProperties;
    
    /**
     * Cookie retriever.
     */
    protected final CookieRetrievingCookieGenerator ticketGrantingTicketCookieGenerator;

}

