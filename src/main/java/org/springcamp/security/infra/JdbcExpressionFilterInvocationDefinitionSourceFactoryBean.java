package org.springcamp.security.infra;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;

public class JdbcExpressionFilterInvocationDefinitionSourceFactoryBean
		implements FactoryBean<ExpressionBasedFilterInvocationSecurityMetadataSource> {
	private AuthorizationMetaService authorizationMetaService;

	public JdbcExpressionFilterInvocationDefinitionSourceFactoryBean(
			AuthorizationMetaService authorizationMetaService) {
		super();
		this.authorizationMetaService = authorizationMetaService;
	}

	public boolean isSingleton() {
		return true;
	}

	public Class<?> getObjectType() {
		return ExpressionBasedFilterInvocationSecurityMetadataSource.class;
	}

	public ExpressionBasedFilterInvocationSecurityMetadataSource getObject() {
		return new ExpressionBasedFilterInvocationSecurityMetadataSource(
				this.executeResourceMap(),
				new DefaultWebSecurityExpressionHandler());
	}

	protected LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> executeResourceMap() {
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap = 
				new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();

		Map<String, String> resourceMap = authorizationMetaService.findAllAuthMetaData();

		for (Map.Entry<String, String> entry : resourceMap.entrySet()) {
			String path = entry.getKey();
			String requiredChannel = entry.getValue();			
			RequestMatcher matcher = new AntPathRequestMatcher(path, null);
			Collection<ConfigAttribute> attrList = SecurityConfig
					.createListFromCommaDelimitedString(requiredChannel);
			requestMap.put(matcher, attrList);
		}
		return requestMap;
	}
}
