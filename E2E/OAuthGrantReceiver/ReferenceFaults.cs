// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Security.Cryptography;
using E2E.OAuthGrantReceiver;

// Test-only extension of the pinned reference. Reuses its parsing/canonicalization and
// policy helpers, omitting exactly one verification stage for hostile-oracle self-tests.
// The normal receiver always calls the unmodified Reference.Verify.
static partial class Reference
{
    public static Outcome VerifyWithDisabledCheck(Vector vector, TestKey[] keys, NonceStore store, DisabledCheck disabled)
    {
        try
        {
            var input = vector.Inputs;
            if (!input.AuthenticatedTls) throw new Rejected("hop");
            var envelope = Parse(vector.Envelope);
            CheckFreshness(envelope.Timestamp, input.Now);
            var key = keys.SingleOrDefault(candidate => candidate.KeyIds.Contains(envelope.Kid)) ?? throw new Rejected("key");
            var (canonical, headers) = Canonical(input, envelope.Parts);
            if (disabled != DisabledCheck.Signature) CheckSignature(canonical, envelope.Signature, key);
            Principal(headers);
            Metadata(headers, input.RealmIssuer);
            var callerSource = disabled == DisabledCheck.BearerBinding ? null : BindForwardedBearer(input, headers);
            if (disabled != DisabledCheck.Replay) CheckReplay(vector, store);
            return new("accept", "ok", callerSource);
        }
        catch (Rejected error) { return new("reject", error.Message); }
    }

    static void CheckFreshness(long timestamp, long now)
    {
        if ((decimal)timestamp < (decimal)now - 60 || (decimal)timestamp > (decimal)now + 30) throw new Rejected("freshness");
    }

    static void CheckReplay(Vector vector, NonceStore store)
    {
        var input = vector.Inputs;
        if (!input.ReplaySensitive) return;
        if (!input.StoreAvailable || input.StoreFull) throw new Rejected("store");
        var envelope = Parse(vector.Envelope);
        if (!store.Reserve(input.Aud, envelope.Kid, envelope.Parts[3], envelope.Timestamp, input.Now)) throw new Rejected("replay");
    }

    static void CheckSignature(byte[] canonical, byte[] signature, TestKey key)
    {
        using var verifier = ECDsa.Create();
        verifier.ImportFromPem(key.PublicKeyPem);
        var verified = false;
        try { verified = verifier.VerifyData(canonical, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (CryptographicException) { /* Match the pinned reference's invalid-scalar rejection. */ }
        if (!verified) throw new Rejected("signature");
    }
}
