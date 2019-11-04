package org.apereo.cas.ticket.code;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.authentication.Authentication;
import org.apereo.cas.authentication.principal.Service;
import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.ticket.ExpirationPolicy;
import org.apereo.cas.ticket.Ticket;
import org.apereo.cas.ticket.TicketFactory;
import org.apereo.cas.ticket.TicketGrantingTicket;
import org.apereo.cas.ticket.UniqueTicketIdGenerator;
import org.apereo.cas.util.DefaultUniqueTicketIdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;

/**
 * Default OAuth code factory.
 *
 * @author Jerome Leleu
 * @since 5.0.0
 */
public class DefaultOAuthCodeFactory implements OAuthCodeFactory {

	static Logger LOGGER = LoggerFactory.getLogger(OAuth20CasAuthenticationBuilder.class);
    /**
     * Default instance for the ticket id generator.
     */
    protected final UniqueTicketIdGenerator oAuthCodeIdGenerator;

    /**
     * ExpirationPolicy for refresh tokens.
     */
    protected final ExpirationPolicy expirationPolicy;

    public DefaultOAuthCodeFactory(UniqueTicketIdGenerator oAuthCodeIdGenerator, ExpirationPolicy expirationPolicy) {
		super();
		this.oAuthCodeIdGenerator = oAuthCodeIdGenerator;
		this.expirationPolicy = expirationPolicy;
	}

	public DefaultOAuthCodeFactory(final ExpirationPolicy expirationPolicy) {
        this(new DefaultUniqueTicketIdGenerator(), expirationPolicy);
    }
    
    @Override
    public OAuthCode create(final Service service, final Authentication authentication,
                            final TicketGrantingTicket ticketGrantingTicket, final Collection<String> scopes) {
        final String codeId = this.oAuthCodeIdGenerator.getNewTicketId(OAuthCode.PREFIX);
        return new OAuthCodeImpl(codeId, service, authentication,
            this.expirationPolicy, ticketGrantingTicket, scopes);
    }

    @Override
    public TicketFactory get(final Class<? extends Ticket> clazz) {
        return this;
    }
}
