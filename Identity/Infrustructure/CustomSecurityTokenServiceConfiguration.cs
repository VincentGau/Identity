using System;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Identity.Infrustructure
{
    public class CustomSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
        private const string SIGNING_CERTIFICATE_NAME = "CN=localhost";
        public CustomSecurityTokenServiceConfiguration() : base("http://localhost:5000", new X509SigningCredentials(CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SIGNING_CERTIFICATE_NAME)))
        {
            SecurityTokenService = typeof(CustomSecurityTokenService);

        }
    }
}