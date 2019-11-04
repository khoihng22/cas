package org.apereo.cas.ticket.refreshtoken;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;

import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.ticket.TicketState;
import org.apereo.cas.ticket.support.AbstractCasExpirationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import groovy.transform.EqualsAndHashCode;
import groovy.util.logging.Slf4j;
import lombok.NoArgsConstructor;

/**
 * This is OAuth refresh token expiration policy (max time to live = 1 month by default).
 *
 * @author Jerome Leleu
 * @since 5.0.0
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@EqualsAndHashCode(callSuper = true)
public class OAuthRefreshTokenExpirationPolicy extends AbstractCasExpirationPolicy {

    private static final long serialVersionUID = -7144233906843566234L;
    
    static Logger LOGGER = LoggerFactory.getLogger(OAuth20CasAuthenticationBuilder.class);

    public OAuthRefreshTokenExpirationPolicy() {
		super();
	}

	/**
     * The time to kill in milliseconds.
     */
    private long timeToKillInSeconds;

    /**
     * Instantiates a new OAuth refresh token expiration policy.
     *
     * @param timeToKillInSeconds the time to kill in seconds
     */
    @JsonCreator
    public OAuthRefreshTokenExpirationPolicy(@JsonProperty("timeToLive") final long timeToKillInSeconds) {
        this.timeToKillInSeconds = timeToKillInSeconds;
    }

    @Override
    public boolean isExpired(final TicketState ticketState) {
        final boolean expired = isRefreshTokenExpired(ticketState);
        if (!expired) {
            return super.isExpired(ticketState);
        }
        return expired;
    }

    @Override
    public Long getTimeToLive() {
        return this.timeToKillInSeconds;
    }

    @JsonIgnore
    @Override
    public Long getTimeToIdle() {
        return 0L;
    }

    /**
     * Is refresh token expired ?
     *
     * @param ticketState the ticket state
     * @return the boolean
     */
    @JsonIgnore
    protected boolean isRefreshTokenExpired(final TicketState ticketState) {
        final ZonedDateTime expiringTime = ticketState.getCreationTime().plus(this.timeToKillInSeconds, ChronoUnit.SECONDS);
        return ticketState == null || expiringTime.isBefore(ZonedDateTime.now(ZoneOffset.UTC));
    }

    /**
     * An expiration policy that is independent from the parent ticket-granting ticket.
     * Activated when refresh tokens are expected to live beyond the normal expiration policy
     * of the TGT that lent a hand in issuing them. If the refresh token is considered expired
     * by this policy, the parent ticket's expiration policy is not consulted, making the RT independent.
     */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @Slf4j
    @EqualsAndHashCode(callSuper = true)
    public static class OAuthRefreshTokenSovereignExpirationPolicy extends OAuthRefreshTokenExpirationPolicy {
        private static final long serialVersionUID = -7768661082888351104L;
        
        public OAuthRefreshTokenSovereignExpirationPolicy() {
        	
        }
        @JsonCreator
        public OAuthRefreshTokenSovereignExpirationPolicy(@JsonProperty("timeToLive") final long timeToKillInSeconds) {
            super(timeToKillInSeconds);
        }

        @Override
        public boolean isExpired(final TicketState ticketState) {
            return isRefreshTokenExpired(ticketState);
        }
    }
}
