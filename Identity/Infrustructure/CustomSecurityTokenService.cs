using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Identity.Infrustructure
{
    public class CustomSecurityTokenService : SecurityTokenService
    {

        static readonly string[] _addressExpected = { };
        //static readonly string _addressExpected = "http://localhost:5001";

        // Certificate Constants
        //private const string SIGNING_CERTIFICATE_NAME = "CN=localhost";
        //private const string ENCRYPTING_CERTIFICATE_NAME = "CN=localhost";
        private const string SIGNING_CERTIFICATE_NAME = "CN=MySTSCert2";
        private const string ENCRYPTING_CERTIFICATE_NAME = "CN=MySTSCert2";

        private SigningCredentials _signingCreds;
        private EncryptingCredentials _encryptingCreds;

        public CustomSecurityTokenService(SecurityTokenServiceConfiguration configuration)
            : base(configuration)
        {
            // Setup the certificate our STS is going to use to sign the issued tokens
            //_signingCreds = new X509SigningCredentials(CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, SIGNING_CERTIFICATE_NAME));
            _signingCreds = new X509SigningCredentials(CertificateUtil.GetCertificateFromFile(System.Web.HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["CertName"])));


            // Note: In this sample app only a si   ngle RP identity is shown, which is localhost, and the certificate of that RP is 
            // populated as _encryptingCreds
            // If you have multiple RPs for the STS you would select the certificate that is specific to 
            // the RP that requests the token and then use that for _encryptingCreds
            //_encryptingCreds = new X509EncryptingCredentials(CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, ENCRYPTING_CERTIFICATE_NAME));
            _encryptingCreds = new X509EncryptingCredentials(CertificateUtil.GetCertificateFromFile(System.Web.HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["CertName"])));
        }


        /// <summary>
        /// This method returns the configuration for the token issuance request. The configuration
        /// is represented by the Scope class. In our case, we are only capable of issuing a token to a
        /// single RP identity represented by the _encryptingCreds field.
        /// </summary>
        /// <param name="principal">The caller's principal</param>
        /// <param name="request">The incoming RST</param>
        /// <returns></returns>
        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            ValidateAppliesTo(request.AppliesTo);
            // Create the scope using the request AppliesTo address and the RP identity
            Scope scope = new Scope(request.AppliesTo.Uri.AbsoluteUri, _signingCreds);

            if (Uri.IsWellFormedUriString(request.ReplyTo, UriKind.Absolute))
            {
                if (request.AppliesTo.Uri.Host != new Uri(request.ReplyTo).Host)
                    scope.ReplyToAddress = request.AppliesTo.Uri.AbsoluteUri;
                else
                    scope.ReplyToAddress = request.ReplyTo;
            }
            else
            {
                Uri resultUri = null;
                if (Uri.TryCreate(request.AppliesTo.Uri, request.ReplyTo, out resultUri))
                    scope.ReplyToAddress = resultUri.AbsoluteUri;
                else
                    scope.ReplyToAddress = request.AppliesTo.Uri.ToString();
            }

            scope.EncryptingCredentials = _encryptingCreds;
            return scope;
        }


        /// <summary>
        /// This method returns the content of the issued token. The content is represented as a set of
        /// IClaimIdentity intances, each instance corresponds to a single issued token. Currently, the Windows Identity Foundation only
        /// supports a single token issuance, so the returned collection must always contain only a single instance.
        /// </summary>
        /// <param name="scope">The scope that was previously returned by GetScope method</param>
        /// <param name="principal">The caller's principal</param>
        /// <param name="request">The incoming RST, we don't use this in our implementation</param>
        protected override ClaimsIdentity GetOutputClaimsIdentity(ClaimsPrincipal principal, RequestSecurityToken request, Scope scope)
        {
            //ClaimsIdentity outgoingIdentity = new ClaimsIdentity();
            //outgoingIdentity.AddClaims(principal.Claims);
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, principal.Identity.Name),
            };

            ClaimsIdentity outgoingIdentity = new ClaimsIdentity(claims);

            return outgoingIdentity;
        }

        void ValidateAppliesTo(EndpointReference appliesTo)
        {
            if (_addressExpected == null || _addressExpected.Length == 0) return;

            var validAppliesTo = Enumerable.Any(_addressExpected, x => appliesTo.Uri.Equals(x));

            if (!validAppliesTo)
            {
                throw new InvalidRequestException(String.Format("The relying party address is not valid. Expected value is {0}, the actual value is {1}.", _addressExpected, appliesTo.Uri.AbsoluteUri));
            }
        }
    }
}