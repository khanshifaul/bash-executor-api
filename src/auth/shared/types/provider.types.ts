export enum AuthProvider {
  LOCAL = 'LOCAL',
  GOOGLE = 'GOOGLE',
  GITHUB = 'GITHUB',
}

export const mapStringToProviderEnum = (provider: string): AuthProvider => {
  const providerMap: { [key: string]: AuthProvider } = {
    local: AuthProvider.LOCAL,
    google: AuthProvider.GOOGLE,
    github: AuthProvider.GITHUB
  };

  const enumValue = providerMap[provider.toLowerCase()];
  if (!enumValue) {
    throw new Error(`Unsupported provider: ${provider}`);
  }

  return enumValue;
};
