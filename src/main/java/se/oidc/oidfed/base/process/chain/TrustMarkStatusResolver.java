/*
 * Copyright 2024 OIDC Sweden
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.oidc.oidfed.base.process.chain;

import com.nimbusds.jwt.SignedJWT;

/**
 * Interface for a resolver that provides Trust Mark revocation data information.
 * <p>
 * This resolver answers the question "is this Trust Mark that I hold still valid", which in OpenID Federation 1.0 is
 * answered by the Trust Mark issuer's Trust Mark Status endpoint. That endpoint takes the Trust Mark itself as its
 * single request parameter, so the whole Trust Mark is passed here rather than its type, subject and issuer. An
 * implementation finds the endpoint in the {@code federation_trust_mark_status_endpoint} parameter of the issuer's
 * {@code federation_entity} metadata.
 * <p>
 * Note that this is not the only way to establish that an Entity holds a Trust Mark. When the Trust Mark itself is not
 * at hand, and only the issuer, the type identifier and the subject are known, the Trust Marked Entities Listing
 * endpoint tells whether the subject is listed for that type, and the Trust Mark endpoint issues a fresh Trust Mark.
 * Neither is covered by this interface.
 */
public interface TrustMarkStatusResolver {

  /**
   * Checks whether the given Trust Mark is still active at its issuer.
   *
   * @param trustMark the Trust Mark to check
   * @return true if the issuer reports the Trust Mark as active, false otherwise
   * @throws TrustMarkStatusException if the status could not be established
   */
  boolean isStatusActive(final SignedJWT trustMark) throws TrustMarkStatusException;

}
