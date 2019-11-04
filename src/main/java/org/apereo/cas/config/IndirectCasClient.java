package org.apereo.cas.config;

import org.pac4j.cas.client.CasClient;
import org.pac4j.cas.config.CasConfiguration;

public class IndirectCasClient extends CasClient {
	
	private CasConfiguration configuration;

	public IndirectCasClient(CasConfiguration configuration) {
		super();
		this.configuration = configuration;
	}

	public CasConfiguration getConfiguration() {
		return configuration;
	}

	public void setConfiguration(CasConfiguration configuration) {
		this.configuration = configuration;
	}
	
}
