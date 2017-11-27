using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace StickerFire.Controllers
{
    public class ErrorController : Controller 
    {
        [Route("Error")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
