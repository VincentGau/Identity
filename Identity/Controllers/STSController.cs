using Identity.Infrustructure;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;

namespace Identity.Controllers
{
    public class STSController : Controller
    {
        public const string Action = "wa";
        public const string SignIn = "wsignin1.0";
        public const string SignOut = "wsignout1.0";

        [Authorize]
        // GET: STS
        public ActionResult Index()
        {
            var action = Request.QueryString[Action];

            if(action == SignIn)
            {
                var formData = ProcessSignIn(Request.Url, (ClaimsPrincipal)User);
                return new ContentResult() { Content = formData, ContentType = "text/html" };
            }

            return View();
        }

        private string ProcessSignIn(Uri url, ClaimsPrincipal user)
        {
            var requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri(url);

            //var _signingCreds = new X509SigningCredentials(CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, "CN=localhost"));
            //var _signingCreds = new X509SigningCredentials(CertificateUtil.GetCertificate(StoreName.My, StoreLocation.LocalMachine, "CN=MySTSCert2"));
            var _signingCreds = new X509SigningCredentials(CertificateUtil.GetCertificateFromFile(System.Web.HttpContext.Current.Server.MapPath(ConfigurationManager.AppSettings["CertName"])));


            var config = new SecurityTokenServiceConfiguration("http://localhost:5000", _signingCreds);
            var sts = new CustomSecurityTokenService(config);

            var responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, user, sts);

            return responseMessage.WriteFormPost();
        }
    }
}