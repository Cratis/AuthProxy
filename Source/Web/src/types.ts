export type OidcProviderType = 'Custom' | 'Microsoft' | 'Google' | 'GitHub' | 'Apple' | 'CratisIdentity';

export interface OidcProvider {
    name: string;
    type: OidcProviderType;
    loginUrl: string;
}
