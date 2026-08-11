// Copyright (c) Cratis. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Cratis.AuthProxy.Admission.given;
using Microsoft.AspNetCore.DataProtection;

namespace Cratis.AuthProxy.Admission.for_AdmissionPolicy.given;

/// <summary>
/// The policy over a real protector and a real key ring, with a clock a spec can move.
/// <para>
/// The protector is the real one rather than a substitute because half of what the policy promises is
/// cryptographic — a value that was altered, truncated or sealed under somebody else's keys has to be
/// indistinguishable from one that was never presented, and a substitute would happily answer for all of
/// them.
/// </para>
/// </summary>
public class an_admission_policy : Specification
{
    protected const string Transaction = "3f9c0a1b7e2d4c6f";
    protected const string Challenge = "8b1d5e7a0c3f2941";

    protected FixedTime _time;
    protected IEntryTransactionProtector _protector;
    protected AdmissionPolicy _policy;
    protected C.AuthProxy _config;
    protected DefaultHttpContext _context;

    void Establish()
    {
        _time = new FixedTime(DateTimeOffset.UtcNow);
        _protector = new EntryTransactionProtector(new EphemeralDataProtectionProvider());
        _policy = new AdmissionPolicy(_protector, _time);

        _config = new C.AuthProxy
        {
            Admission = new C.Admission
            {
                Mode = C.AdmissionMode.CapabilityOnly,
                Capability = new C.AdmissionCapability { VerifierUrl = "https://verifier.test/admit" },
            },
        };

        _context = new DefaultHttpContext();
        _context.Request.Path = "/";
    }

    /// <summary>
    /// Seals an entry transaction expiring the given distance from now.
    /// </summary>
    /// <param name="expiresIn">How far ahead of the current clock it expires.</param>
    /// <returns>The protected value.</returns>
    protected string SealedTransaction(TimeSpan expiresIn) =>
        _protector.Protect(new EntryTransaction(
            Transaction,
            Challenge,
            _time.GetUtcNow().Add(expiresIn),
            new Dictionary<string, string>(StringComparer.Ordinal)));

    /// <summary>
    /// Puts the given cookies on the request.
    /// </summary>
    /// <param name="cookies">The cookies, as <c>name=value</c> pairs.</param>
    protected void Presenting(params string[] cookies) =>
        _context.Request.Headers.Cookie = string.Join("; ", cookies);
}
