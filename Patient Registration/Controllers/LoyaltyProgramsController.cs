using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Patient_Registration.Data;
using Patient_Registration.Models;

namespace Patient_Registration.Controllers
{
    public class LoyaltyProgramsController : Controller
    {
        private readonly RegisterDb _context;

        public LoyaltyProgramsController(RegisterDb context)
        {
            _context = context;
        }

        // GET: LoyaltyPrograms
        public async Task<IActionResult> Index()
        {
            var sessionValue = HttpContext.Session.GetString("loggeduser");
            if ((sessionValue == "none") || (sessionValue == null))
            {
                return RedirectToAction("Signin", "Users");
            }
            else
            {
                return View(await _context.Call_LoyaltyPrograms.Where(x => x.Active =="true").ToListAsync());
            }
                           
        }

        // GET: LoyaltyPrograms/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_LoyaltyPrograms = await _context.Call_LoyaltyPrograms
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_LoyaltyPrograms == null)
            {
                return NotFound();
            }

            return View(call_LoyaltyPrograms);
        }

        // GET: LoyaltyPrograms/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: LoyaltyPrograms/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,LoyaltyName,LoyaltyDescription,Active")] Call_LoyaltyPrograms call_LoyaltyPrograms)
        {
            if (ModelState.IsValid)
            {
                _context.Add(call_LoyaltyPrograms);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(call_LoyaltyPrograms);
        }

        // GET: LoyaltyPrograms/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_LoyaltyPrograms = await _context.Call_LoyaltyPrograms.FindAsync(id);
            if (call_LoyaltyPrograms == null)
            {
                return NotFound();
            }
            return View(call_LoyaltyPrograms);
        }

        // POST: LoyaltyPrograms/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,LoyaltyName,LoyaltyDescription,Active")] Call_LoyaltyPrograms call_LoyaltyPrograms)
        {
            if (id != call_LoyaltyPrograms.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(call_LoyaltyPrograms);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!Call_LoyaltyProgramsExists(call_LoyaltyPrograms.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(call_LoyaltyPrograms);
        }

        // GET: LoyaltyPrograms/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_LoyaltyPrograms = await _context.Call_LoyaltyPrograms
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_LoyaltyPrograms == null)
            {
                return NotFound();
            }

            return View(call_LoyaltyPrograms);
        }

        // POST: LoyaltyPrograms/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var call_LoyaltyPrograms = await _context.Call_LoyaltyPrograms.FindAsync(id);
            if (call_LoyaltyPrograms != null)
            {
                call_LoyaltyPrograms.Active = "false";
                _context.Update(call_LoyaltyPrograms);
                //_context.Call_LoyaltyPrograms.Remove(call_LoyaltyPrograms);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool Call_LoyaltyProgramsExists(int id)
        {
            return _context.Call_LoyaltyPrograms.Any(e => e.Id == id);
        }
    }
}
