using Microsoft.Identity.Client;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security;
using System.Threading.Tasks;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        public TestContext TestContext { get; set; }
        string B2CAppId = "a7bb8dac-fdda-42f0-b277-b9c4e5ca0dac";

        [TestMethod]
        public async Task TestAsync()
        {
            string secret = Environment.GetEnvironmentVariable("kvsecret");

            KeyVaultSecretFetcher fetcher = new KeyVaultSecretFetcher(secret);
            var userPassword = await fetcher.FetchUserAsync().ConfigureAwait(false);

            IPublicClientApplication publicClient = PublicClientApplicationBuilder
                .Create(B2CAppId)
                .WithB2CAuthority("https://bgavrilb2c.b2clogin.com/tfp/bgavrilb2c.onmicrosoft.com/b2c_1_ropc")
                .Build();

            SecureString secureString = new SecureString();
            foreach (char c in userPassword.Password)
            {
                secureString.AppendChar(c);
            }

            var result = await publicClient.AcquireTokenByUsernamePassword(
                new[] { "https://bgavrilb2c.onmicrosoft.com/hello3/user_impersonation" },
                userPassword.User,
                secureString).ExecuteAsync();

            Assert.IsNotNull(result);
        }
    }
}
