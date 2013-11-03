package org.springcamp.security.infra;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.expression.ExpressionParser;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.AntPathRequestMatcher;
import org.springframework.security.web.util.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

public class ExpressionSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
	private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();;
	private AuthorizationMetaService urlRepositoryMapping;

	public ExpressionSecurityMetadataSource(AuthorizationMetaService urlRepositoryMapping) {
		super();
		this.urlRepositoryMapping = urlRepositoryMapping;
	}
	public ExpressionSecurityMetadataSource(AuthorizationMetaService urlRepositoryMapping, SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		super();
		this.urlRepositoryMapping = urlRepositoryMapping;
		this.expressionHandler = expressionHandler;
	}
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
        final HttpServletRequest request = ((FilterInvocation) object).getRequest();
        Map<RequestMatcher, Collection<ConfigAttribute>> map = executeResourceMap();
        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : map.entrySet()) {
            if (entry.getKey().matches(request)) {
                return entry.getValue();
            }
        }
        return null;
	}
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<Entry<RequestMatcher, Collection<ConfigAttribute>>> resourceEntry = executeResourceMap().entrySet();
        Set<ConfigAttribute> allAttributes = new HashSet<ConfigAttribute>(resourceEntry.size());

        for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : resourceEntry) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
	}

    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
    }

	/*@Cacheable(value="mobile.common.framework.spring.security.voter.UrlRepositoryMapping", key="#root.methodName")*/
	public LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> executeResourceMap() {
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap =
				new LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>>();

		// ConfigAttributeEditor editor = new ConfigAttributeEditor();
		Map<String, String> resourceMap = urlRepositoryMapping.findAllAuthMetaData();

		for (Map.Entry<String, String> entry : resourceMap.entrySet()) {
			RequestMatcher matcher = new AntPathRequestMatcher(entry.getKey(), null);
			Collection<ConfigAttribute> attrList = createExpressionListFromCommaDelimitedString(entry.getValue());
			requestMap.put(matcher, attrList);
		}
		return requestMap;
	}
    public List<ConfigAttribute> createExpressionListFromCommaDelimitedString(String access) {
        return createExpressionList(StringUtils.commaDelimitedListToStringArray(access));
    }

    public List<ConfigAttribute> createExpressionList(String... attributeNames) {
        Assert.notNull(attributeNames, "You must supply an array of attribute names");
        List<ConfigAttribute> attributes = new ArrayList<ConfigAttribute>(attributeNames.length);
        ExpressionParser parser = expressionHandler.getExpressionParser();
        for (String attribute : attributeNames) {
            attributes.add(new ExternalWebExpressionConfigAttribute(parser.parseExpression(attribute)));
        }

        return attributes;
    }
}
