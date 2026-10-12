/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authentication.authenticators.resetcred;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Regression tests for the reset-password token invalidation lifespan logic.
 *
 * <p>When a new reset-password token is issued, any previously issued token is invalidated by storing
 * it in the single-use object store for its remaining lifespan. That store requires a <em>positive</em>
 * lifespan and throws {@link IllegalArgumentException} for anything else, so a token that has already
 * expired must be skipped rather than stored with a negative/zero lifespan. These tests pin that
 * decision so the already-expired case cannot silently regress.
 */
public class ResetCredentialEmailTest {

    private static final long NOW = 1_000_000L;

    @Test
    public void remainingLifespanIsPositiveForAnActiveToken() {
        assertThat(ResetCredentialEmail.remainingLifespanSeconds(NOW + 300, NOW), is(300L));
    }

    @Test
    public void remainingLifespanIsNegativeForAnExpiredToken() {
        assertThat(ResetCredentialEmail.remainingLifespanSeconds(NOW - 300, NOW), is(-300L));
    }

    @Test
    public void remainingLifespanIsZeroForATokenExpiringExactlyNow() {
        assertThat(ResetCredentialEmail.remainingLifespanSeconds(NOW, NOW), is(0L));
    }

    @Test
    public void remainingLifespanIsComputedInLongSpaceToAvoidOverflow() {
        // Far-future expiry beyond Integer.MAX_VALUE: the subtraction must not overflow.
        long farFuture = (long) Integer.MAX_VALUE + 1_000L;
        assertThat(ResetCredentialEmail.remainingLifespanSeconds(farFuture, 0L), is(farFuture));
    }

    @Test
    public void activeTokenIsInvalidated() {
        // A positive remaining lifespan means the previous token is still usable and must be invalidated.
        assertThat(ResetCredentialEmail.shouldInvalidate(300L), is(true));
    }

    @Test
    public void expiredTokenIsNotInvalidated() {
        // The regression: an already-expired token must NOT be put into the single-use store (that call
        // would throw IllegalArgumentException because the lifespan is non-positive).
        assertThat(ResetCredentialEmail.shouldInvalidate(-300L), is(false));
    }

    @Test
    public void tokenExpiringExactlyNowIsNotInvalidated() {
        // Zero lifespan is also non-positive and would be rejected by the store, so it is skipped.
        assertThat(ResetCredentialEmail.shouldInvalidate(0L), is(false));
    }
}
