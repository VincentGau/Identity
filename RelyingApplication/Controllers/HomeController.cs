using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Web;
using System.Web.Mvc;

namespace RelyingApplication.Controllers
{
    public class HomeController : Controller
    {
        [CustomAuthorize(Roles = "testRole,testRole2")]
        public ActionResult Index()
        {
            ViewBag.ClaimsIdentity = Thread.CurrentPrincipal.Identity;
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}