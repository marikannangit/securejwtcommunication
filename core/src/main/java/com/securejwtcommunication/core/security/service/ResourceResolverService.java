package com.securejwtcommunication.core.security.service;

import org.apache.sling.api.resource.ResourceResolver;


/**
 * Service for obtaining {@link ResourceResolver} instances.
 */
public interface ResourceResolverService {

    /**
     * Gets a {@link ResourceResolver} for the specified service user.
     *
     * @param serviceUser the name of the service user.
     * @return a {@link ResourceResolver} for the given service user.
     */
    ResourceResolver getResourceResolver(String serviceUser);
}

