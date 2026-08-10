// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Cratis.AuthProxy.Identity.for_IdentityAuthorizationCache.when_recording_with_verification_required;

/// <summary>
/// A zero re-validation interval is documented as "no bound", and the released fallback quietly turned that
/// into ten minutes — the longest lifetime the setting can produce. Harmless while the record only saves a
/// round-trip; the opposite of what was asked for once it carries an authorization decision, because the
/// deployment that wanted nothing remembered would be handed the most permissive memory available.
/// <para>
/// Where the identity endpoint is a verifier, "no bound" is honored by recording nothing at all.
/// </para>
/// </summary>
public class and_revalidation_is_disabled : given.a_verifying_deployment
{
    void Establish() => _configuration.Session.IdentityRevalidationInterval = TimeSpan.Zero;

    void Because() => _cache.Record(_context, new ClientPrincipal { UserId = "user-1" }, TenantId);

    [Fact] void should_not_record_a_positive_at_all() => RecordWasWritten().ShouldBeFalse();
}
