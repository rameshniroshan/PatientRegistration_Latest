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
    public class GuardianController : Controller
    {
        private readonly RegisterDb _context;

        public GuardianController(RegisterDb context)
        {
            _context = context;
        }

        // GET: Guardian
        public async Task<IActionResult> Index()
        {
            return View(await _context.Call_Guardian.ToListAsync());
        }

        // GET: Guardian/Details/5
        public async Task<IActionResult> Details(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Guardian = await _context.Call_Guardian
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_Guardian == null)
            {
                return NotFound();
            }

            return View(call_Guardian);
        }

        // GET: Guardian/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Guardian/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("Id,MobileNo,GuardianPatientName")] Call_Guardian call_Guardian)
        {
            if (ModelState.IsValid)
            {
                _context.Add(call_Guardian);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(call_Guardian);
        }

        // GET: Guardian/Edit/5
        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Guardian = await _context.Call_Guardian.FindAsync(id);
            if (call_Guardian == null)
            {
                return NotFound();
            }
            return View(call_Guardian);
        }

        // POST: Guardian/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,MobileNo,GuardianPatientName")] Call_Guardian call_Guardian)
        {
            if (id != call_Guardian.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(call_Guardian);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!Call_GuardianExists(call_Guardian.Id))
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
            return View(call_Guardian);
        }

        // GET: Guardian/Delete/5
        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Guardian = await _context.Call_Guardian
                .FirstOrDefaultAsync(m => m.Id == id);
            if (call_Guardian == null)
            {
                return NotFound();
            }

            return View(call_Guardian);
        }

        // POST: Guardian/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var call_Guardian = await _context.Call_Guardian.FindAsync(id);
            if (call_Guardian != null)
            {
                _context.Call_Guardian.Remove(call_Guardian);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool Call_GuardianExists(int id)
        {
            return _context.Call_Guardian.Any(e => e.Id == id);
        }
    }
}
