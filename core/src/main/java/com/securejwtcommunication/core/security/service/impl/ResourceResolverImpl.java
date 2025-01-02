package com.securejwtcommunication.core.security.service.impl;

import com.securejwtcommunication.core.security.service.ResourceResolverService;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.osgi.service.component.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Service implementation for obtaining {@link ResourceResolver} instances.
 * <p>
 * This OSGi component provides a {@link ResourceResolver} for a specified service user.
 * </p>
 */
@Component(
        service = ResourceResolverService.class,
        immediate = true,
        name = "Resource resolver service",
        configurationPolicy = ConfigurationPolicy.OPTIONAL
)
public class ResourceResolverImpl implements ResourceResolverService {

    private final Logger LOGGER = LoggerFactory.getLogger(ResourceResolverImpl.class);

    @Reference
    private ResourceResolverFactory resourceResolverFactory;

    /**
     * Returns a {@link ResourceResolver} for the given service user.
     *
     * @param serviceUser the name of the service user.
     * @return the {@link ResourceResolver}, or {@code null} if an error occurs.
     */
    @Override
    public ResourceResolver getResourceResolver(String serviceUser) {
        ResourceResolver resourceResolver = null;
        try {
            Map<String, Object> paramMap = new HashMap<>();
            paramMap.put(ResourceResolverFactory.SUBSERVICE, serviceUser);
            resourceResolver = resourceResolverFactory.getServiceResourceResolver(paramMap);
        } catch (LoginException e) {
            LOGGER.error("Failed to obtain ResourceResolver for service user: {}", serviceUser, e);
        }
        return resourceResolver;
    }

    /**
     * Called when the component is activated.
     */
    @Activate
    protected void activate() {
        LOGGER.info("activate >> Start");
        LOGGER.info("activate >> Complete");;
    }

    /**
     * Called when the component is deactivated.
     */
    @Deactivate
    protected void deactivate() {
        LOGGER.info("deactivate >> Start");
        LOGGER.info("deactivate >> Complete");
    }
}
