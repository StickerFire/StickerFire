﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using StickerFire.Data;
using StickerFire.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using LogLevel = Microsoft.Extensions.Logging.LogLevel;
using Microsoft.AspNetCore.Identity;

namespace StickerFire.Controllers
{
    public class CampaignController : Controller
    {   

        private readonly StickerFireDbContext _Context;
        private readonly UserManager<ApplicationUser> _user;

        //Cunstructor to requier a DbContext 
        public CampaignController(UserManager<ApplicationUser> userManager,StickerFireDbContext context)
        {
            _Context = context;
            _user = userManager;
        }

        //Index Gathering all campaigns from the Context
        public async Task<IActionResult> Index(Category? category, string searchString)
        {
          
            if (!String.IsNullOrEmpty(searchString))
            {
                
                return View(await _Context.Campaign.Where(c => c.Title.Contains(searchString)).ToListAsync());
            }
            
            if (category.HasValue)
            {
                return View(await _Context.Campaign.Where(c => c.Category == category).ToListAsync());
            }

            return View(await _Context.Campaign.ToListAsync());
            
        }
        //MyCampaigns: This will navigate to the users campaign campaigns

        public async Task<IActionResult> MyCampaigns()
        {
            string userEmail = HttpContext.User.Identity.Name;

            ApplicationUser user = await _user.FindByEmailAsync(userEmail);

            var myCampaigns = await _Context.Campaign.Where(c => c.OwnerID == user.Id).ToListAsync();

            return View(myCampaigns);
        }

        //Get the create View
        public IActionResult Create()
        {
            return View();
        }
        //Post method to bind the entered campaign information into the database with AntiForgery Token
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("ID,OwnerID,Votes,Views,Title,ImgPath,Description,DenyMessage,Published,Active,Category,Status")]Campaign campaign)
        {
            string userEmail = HttpContext.User.Identity.Name;

            ApplicationUser user = await _user.FindByEmailAsync(userEmail);

            if (ModelState.IsValid)
            {
                var title = campaign.Title;
                var path = campaign.ImgPath;

                await Blob.MakeAContainer(user.Id);
                await Blob.UploadBlob(user.Id, title, path);


                _Context.Add(campaign);
                await _Context.SaveChangesAsync();
                //return CreatedAtAction("Create", new { id = campaign.ID }, campaign);
            return RedirectToAction(nameof(Index));
            }

            //return View(campaign);
            return View();


        }


        //This Method will find the selected campaing and render the page for editing
        public async Task<IActionResult>Edit(int? id)

        {
            if (id == null)
            {
                return NotFound();
            }

            var campaign = await _Context.Campaign
                .SingleOrDefaultAsync(c => c.ID == id);

            if (campaign == null)
            {
                return NotFound();
            }
            return View(campaign);
        }

        //Post for the Edit method with Aniforgery Token
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("ID,OwnerID,Votes,Views,ImgPath,Description,DenyMessage,Published,Active,Category,Status")]Campaign campaign)
        {
            if (id != campaign.ID)
            {
                return NotFound();
            }
            if (ModelState.IsValid)
            {
                _Context.Update(campaign);
                await _Context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
                return View(campaign);
        }

        //Get Method that will grab the campaing selected for deletion
        public async Task<IActionResult> Delete(int? id)
        {
            if(id == null)
            {
                return NotFound();
            }

            var campaign = await _Context.Campaign
                .SingleOrDefaultAsync(m => m.ID == id);
            if(campaign == null)
            {
                return NotFound(); 
            }
            return View(campaign);
        }

        //This will delete the celected campaign
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var campaign = await _Context.Campaign
                .SingleOrDefaultAsync(m => m.ID == id);

            _Context.Campaign.Remove(campaign);
            await _Context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        //May need a CampaignExists Method to check if the campaign that is being deleted. 
    }
}
