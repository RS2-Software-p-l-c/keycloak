package org.keycloak.saml.processing.core.saml.v2.util;

import org.keycloak.saml.common.exceptions.ProcessingException;

public class DecryptionException extends ProcessingException {
    public DecryptionException(Throwable cause) {
        super(cause);
    }
}
