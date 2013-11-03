package org.springcamp.security.infra;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.config.http.ChannelAttributeFactory;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.StringUtils;

public class JdbcChannelFilterInvocationDefinitionSourceFactoryBean implements
		FactoryBean<DefaultFilterInvocationSecurityMetadataSource> {
	private AuthorizationMetaService authorizationMetaService;

	public JdbcChannelFilterInvocationDefinitionSourceFactoryBean(
			AuthorizationMetaService authorizationMetaService) {
		super();
		this.authorizationMetaService = authorizationMetaService;
	}

	public boolean isSingleton() {
		return true;
	}

	public Class<?> getObjectType() {
		return DefaultFilterInvocationSecurityMetadataSource.class;
	}

	public DefaultFilterInvocationSecurityMetadataSource getObject() {
		return new DefaultFilterInvocationSecurityMetadataSource(
				this.executeResourceMap());
	}

	/**
	 * DB에서 조회한 데이터로 URL, CHANNEL Map을 생성
	 * 
	 * @return
	 */
	protected Map<String, String> getAuthorizationMetaInfo() {
		Map<String, String> resourceMap = new LinkedHashMap<String, String>();
		for (AuthorizationMeta repo : authorizationMetaService.getRepositoryList()) {
			String path = repo.getPath();
			String channel = repo.getSecurityChannel();
			resourceMap.put(path, channel);
		}

		return resourceMap;
	}

	protected LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> executeResourceMap() {
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = null;
		requestMap = new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();

		Map<String, String> resourceMap = this.getAuthorizationMetaInfo();

		for (Map.Entry<String, String> entry : resourceMap.entrySet()) {
			String path = entry.getKey();
			String requiredChannel = entry.getValue();
			if (StringUtils.hasText(requiredChannel)) {
				RequestMatcher matcher = new AntPathRequestMatcher(path, null);
				requestMap.put(matcher, ChannelAttributeFactory
						.createChannelAttributes(requiredChannel));
			}
		}
		return requestMap;
	}
}
