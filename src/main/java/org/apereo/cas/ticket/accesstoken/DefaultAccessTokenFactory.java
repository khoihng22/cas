package org.apereo.cas.ticket.accesstoken;

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
 * Default OAuth access token factory.
 *
 * @author Jerome Leleu
 * @since 5.0.0
 */
public class DefaultAccessTokenFactory implements AccessTokenFactory {
	
	static Logger LOGGER = LoggerFactory.getLogger(OAuth20CasAuthenticationBuilder.class);

    /** Default instance for the ticket id generator. */
    protected final UniqueTicketIdGenerator accessTokenIdGenerator;

    /** ExpirationPolicy for refresh tokens. */
    protected final ExpirationPolicy expirationPolicy;

    public UniqueTicketIdGenerator getAccessTokenIdGenerator() {
		return accessTokenIdGenerator;
	}

	public ExpirationPolicy getExpirationPolicy() {
		return expirationPolicy;
	}

	public DefaultAccessTokenFactory(final ExpirationPolicy expirationPolicy) {
        this(new DefaultUniqueTicketIdGenerator(), expirationPolicy);
    }

	public DefaultAccessTokenFactory(UniqueTicketIdGenerator accessTokenIdGenerator,
			ExpirationPolicy expirationPolicy) {
		super();
		this.accessTokenIdGenerator = accessTokenIdGenerator;
		this.expirationPolicy = expirationPolicy;
	}

	@Override
    public AccessToken create(final Service service, final Authentication authentication,
                              final TicketGrantingTicket ticketGrantingTicket, final Collection<String> scopes) {
        final String codeId = this.accessTokenIdGenerator.getNewTicketId(AccessToken.PREFIX);
        final AccessToken at = new AccessTokenImpl(codeId, service, authentication, 
                this.expirationPolicy, ticketGrantingTicket, scopes);
        if (ticketGrantingTicket != null) {
            ticketGrantingTicket.getDescendantTickets().add(at.getId());
        }
        return at;
    }

    @Override
    public TicketFactory get(final Class<? extends Ticket> clazz) {
        return this;
    }
}
