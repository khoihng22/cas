package org.apereo.cas.ticket.code;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.extern.slf4j.Slf4j;

import org.apereo.cas.support.oauth.authenticator.OAuth20CasAuthenticationBuilder;
import org.apereo.cas.ticket.support.MultiTimeUseOrTimeoutExpirationPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is {@link OAuthCodeExpirationPolicy}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@JsonTypeInfo(use=JsonTypeInfo.Id.CLASS, include= JsonTypeInfo.As.PROPERTY)
public class OAuthCodeExpirationPolicy extends MultiTimeUseOrTimeoutExpirationPolicy {
	
	static Logger LOGGER = LoggerFactory.getLogger(OAuth20CasAuthenticationBuilder.class);
	
    private static final long serialVersionUID = -8383186621682727360L;

    /**
     * Instantiates a new O auth code expiration policy.
     *
     * @param numberOfUses             the number of uses
     * @param timeToKillInMilliSeconds the time to kill in milli seconds
     */
    public OAuthCodeExpirationPolicy(@JsonProperty("numberOfUses") final int numberOfUses,
                                     @JsonProperty("timeToLive") final long timeToKillInMilliSeconds) {
        super(numberOfUses, timeToKillInMilliSeconds);
    }
}
