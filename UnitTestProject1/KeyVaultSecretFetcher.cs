using Microsoft.Azure.KeyVault;
using Microsoft.Identity.Client;
using System;
using System.Security;
using System.Threading.Tasks;

namespace UnitTestProject1
{
    public class UserAndPassword
    {
        public string User { get; set; }
        public string Password { get; set; }
    }

    /// <remarks>
    /// Note: Azure DevOps has a task named Azure Key Valut Task that can pull secrets directly 
    /// into a CI pipeline. It is easier to use than writing custom code. However, the approach outlined 
    /// here is useful for understanding how to interact with Azure services.
    /// 
    /// https://github.com/microsoft/azure-pipelines-tasks/blob/master/Tasks/AzureKeyVaultV1/README.md
    /// </remarks>
    public class KeyVaultSecretFetcher
    {
        private const string KeyVaultClientId = "4bf2b2cf-1fec-4ee9-8d95-e862d8d425a6";
        private readonly KeyVaultClient _keyVaultClient;
        private readonly string _secret;

        public KeyVaultSecretFetcher(string secret)
        {
            _keyVaultClient = new KeyVaultClient(KeyVaultAuthenticationCallback);
            _secret = secret;
        }

        public async Task<UserAndPassword> FetchUserAsync()
        {
            // TODO: consider fetching more secrets at once to make this faster, see GetSecretsAsync 
            var username = await _keyVaultClient.GetSecretAsync("https://bogavril-kv.vault.azure.net/secrets/test-username");
            var password = await _keyVaultClient.GetSecretAsync("https://bogavril-kv.vault.azure.net/secrets/test-password");

            return new UserAndPassword() { User = username.Value, Password = password.Value };
        }

        private async Task<string> KeyVaultAuthenticationCallback(string authority, string resource, string scope)
        {
            if (string.IsNullOrEmpty(_secret))
            {
                throw new InvalidOperationException("Test Setup Error: Could not find a setting named kvsecret");
            }

            IConfidentialClientApplication cca = ConfidentialClientApplicationBuilder
                    .Create(KeyVaultClientId)
                    .WithAuthority(new Uri(authority), true)
                    .WithClientSecret(_secret)
                    .Build();

            // KeyVault uses "old style" resources - this is how you transform a resource to a scope
            var scopes = new[] { resource + "/.default" };

            // Tokens will be available even after restarting the application
            TokenCacheHelper.EnableSerialization(cca.AppTokenCache);

            // AcquireTokenForClient is the only call where `AcquireTokenSilent` is not needed
            // because AcquireTokenForClient uses an application cache directly (not the user cache!) 
            var authResult = await cca
                .AcquireTokenForClient(scopes)
                .ExecuteAsync()
                .ConfigureAwait(false);

            return authResult.AccessToken;

        }
    }
}
