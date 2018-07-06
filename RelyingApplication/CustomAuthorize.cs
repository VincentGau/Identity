using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Mvc;

namespace RelyingApplication
{
    public class CustomAuthorize : AuthorizeAttribute
    {
        protected override bool AuthorizeCore(HttpContextBase httpContext)
        {
            bool isAuthorized = base.AuthorizeCore(httpContext);

            if (isAuthorized)
            {
                if (Thread.CurrentPrincipal.Identity.IsAuthenticated)
                {
                    return true;
                }
                    
            }
            
            return false;
        }
    }
}