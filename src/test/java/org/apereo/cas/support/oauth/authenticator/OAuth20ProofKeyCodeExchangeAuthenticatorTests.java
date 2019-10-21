package org.apereo.cas.support.oauth.authenticator;

import org.apereo.cas.mock.MockTicketGrantingTicket;
import org.apereo.cas.services.RegisteredServiceAccessStrategyAuditableEnforcer;
import org.apereo.cas.services.RegisteredServiceTestUtils;
import org.apereo.cas.support.oauth.OAuth20Constants;
import org.apereo.cas.support.oauth.services.OAuth20RegisteredServiceCipherExecutor;
import org.apereo.cas.ticket.code.OAuthCodeImpl;
import org.apereo.cas.ticket.expiration.HardTimeoutExpirationPolicy;
import org.apereo.cas.util.DigestUtils;
import org.apereo.cas.util.EncodingUtils;

import lombok.val;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.pac4j.core.context.JEEContext;
import org.pac4j.core.credentials.UsernamePasswordCredentials;
import org.pac4j.core.exception.CredentialsException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is {@link OAuth20ProofKeyCodeExchangeAuthenticatorTests}.
 *
 * @author Misagh Moayyed
 * @since 6.0.0
 */
@Tag("OAuth")
public class OAuth20ProofKeyCodeExchangeAuthenticatorTests extends BaseOAuth20AuthenticatorTests {
    protected OAuth20ProofKeyCodeExchangeAuthenticator authenticator;

    @BeforeEach
    public void init() {
        authenticator = new OAuth20ProofKeyCodeExchangeAuthenticator(servicesManager, serviceFactory,
            new RegisteredServiceAccessStrategyAuditableEnforcer(), ticketRegistry,
            new OAuth20RegisteredServiceCipherExecutor());
    }

    @Test
    public void verifyAuthenticationPlain() {
        val credentials = new UsernamePasswordCredentials("client", "ABCD123");
        val request = new MockHttpServletRequest();
        ticketRegistry.addTicket(new OAuthCodeImpl("CODE-1234567890", RegisteredServiceTestUtils.getService(), RegisteredServiceTestUtils.getAuthentication(),
            new HardTimeoutExpirationPolicy(10),
            new MockTicketGrantingTicket("casuser"),
            new ArrayList<>(), "ABCD123",
            "plain", "clientid12345", new HashMap<>()));
        request.addParameter(OAuth20Constants.CODE, "CODE-1234567890");
        val ctx = new JEEContext(request, new MockHttpServletResponse());
        authenticator.validate(credentials, ctx);
        assertNotNull(credentials.getUserProfile());
        assertEquals("client", credentials.getUserProfile().getId());
    }

    @Test
    public void verifyAuthenticationHashed() {
        val hash = EncodingUtils.encodeUrlSafeBase64(DigestUtils.sha256("ABCD1234").getBytes(StandardCharsets.UTF_8));
        val credentials = new UsernamePasswordCredentials("client", "ABCD1234");
        val request = new MockHttpServletRequest();
        val ticket = new OAuthCodeImpl("CODE-1234567890",
            RegisteredServiceTestUtils.getService(), RegisteredServiceTestUtils.getAuthentication(),
            new HardTimeoutExpirationPolicy(10),
            new MockTicketGrantingTicket("casuser"),
            new ArrayList<>(), hash, "s256", "clientid12345", new HashMap<>());
        ticketRegistry.addTicket(ticket);
        request.addParameter(OAuth20Constants.CODE, ticket.getId());
        val ctx = new JEEContext(request, new MockHttpServletResponse());
        authenticator.validate(credentials, ctx);
        assertNotNull(credentials.getUserProfile());
        assertEquals("client", credentials.getUserProfile().getId());
    }

    @Test
    public void verifyAuthenticationNotHashedCorrectly() {
        val credentials = new UsernamePasswordCredentials("client", "ABCD1234");
        val request = new MockHttpServletRequest();
        val ticket = new OAuthCodeImpl("CODE-1234567890",
            RegisteredServiceTestUtils.getService(), RegisteredServiceTestUtils.getAuthentication(),
            new HardTimeoutExpirationPolicy(10),
            new MockTicketGrantingTicket("casuser"),
            new ArrayList<>(),
            "something-else", "s256", "clientid12345", new HashMap<>());
        ticketRegistry.addTicket(ticket);
        request.addParameter(OAuth20Constants.CODE, ticket.getId());
        val ctx = new JEEContext(request, new MockHttpServletResponse());
        assertThrows(CredentialsException.class, () -> authenticator.validate(credentials, ctx));
    }
}
