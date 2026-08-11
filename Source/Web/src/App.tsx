import { useEffect, useState } from 'react';
import { ProviderButton } from './components/ProviderButton';
import type { OidcProvider } from './types';

const reasonMessages: Record<string, string> = {
    'remote-failure': 'Signing in did not complete. Please try again.',
    'access-denied': 'The sign-in was cancelled or not approved at the identity provider. Please try again.',
    'invalid-session': 'Your session is no longer valid. Please sign in again.'
};

export default function App() {
    const [providers, setProviders] = useState<OidcProvider[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(false);

    const query = new URLSearchParams(window.location.search);
    const returnUrl = query.get('returnUrl') ?? '/';
    const reason = query.get('reason');
    const reasonMessage = reason ? reasonMessages[reason] : undefined;

    useEffect(() => {
        fetch('/.cratis/providers')
            .then(response => {
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                return response.json() as Promise<OidcProvider[]>;
            })
            .then(data => {
                setProviders(data);
                setLoading(false);
            })
            .catch(() => {
                setError(true);
                setLoading(false);
            });
    }, []);

    const showError = error || (!loading && providers.length === 0);

    return (
        <div className="card">
            <h1>Sign In</h1>
            {reasonMessage && <p className="reason">{reasonMessage}</p>}
            {!loading && !showError && <p>Choose how you want to sign in:</p>}
            {!loading && !showError && (
                <div className="providers">
                    {providers.map(provider => (
                        <ProviderButton key={provider.name} provider={provider} returnUrl={returnUrl} />
                    ))}
                </div>
            )}
            {showError && (
                <p className="error">Unable to load sign-in options. Please refresh the page.</p>
            )}
        </div>
    );
}
