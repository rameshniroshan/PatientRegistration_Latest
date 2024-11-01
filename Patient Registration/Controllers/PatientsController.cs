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
    public class PatientsController : Controller
    {
        private readonly RegisterDb _context;

        public PatientsController(RegisterDb context)
        {
            _context = context;
        }

        // GET: Patients
        //public async Task<IActionResult> Index()
        //{
        //    return View(await _context.Call_Patients.ToListAsync());
        //}

        public async Task<IActionResult> Index(string searchTerm)
        {
            var patients = from p in _context.Call_Patients
                           select p;

            if (!string.IsNullOrEmpty(searchTerm))
            {
                patients = patients.Where(p => p.Name.Contains(searchTerm) || p.FamilyId.ToString().Contains(searchTerm) || p.MobileNo.Contains(searchTerm));
            }

            return View(await patients.ToListAsync());
        }

        // GET: Patients/Details/5
        public async Task<IActionResult> Details(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Patients = await _context.Call_Patients
                .FirstOrDefaultAsync(m => m.MobileNo == id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

        // GET: Patients/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST: Patients/Create
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("MobileNo,NIC,PassportNo,Designation,Name,Surname,DOB,Gender,ResidentArea,Nationality,Religion,GuardianID,GuardianName,RelationGuardian,LoyaltyNo,MemberID,Email,SpecialConditions,SocialId,FamilyId")] Call_Patients call_Patients)
        {
            if (ModelState.IsValid)
            {
                _context.Add(call_Patients);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(call_Patients);
        }

        // GET: Patients/Edit/5
        public async Task<IActionResult> Edit(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Patients = await _context.Call_Patients.FindAsync(id);
            if (call_Patients == null)
            {
                return NotFound();
            }
            return View(call_Patients);
        }

        // POST: Patients/Edit/5
        // To protect from overposting attacks, enable the specific properties you want to bind to.
        // For more details, see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(string id, [Bind("MobileNo,NIC,PassportNo,Designation,Name,Surname,DOB,Gender,ResidentArea,Nationality,Religion,GuardianID,GuardianName,RelationGuardian,LoyaltyNo,MemberID,Email,SpecialConditions,SocialId,FamilyId")] Call_Patients call_Patients)
        {
            if (id != call_Patients.MobileNo)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    _context.Update(call_Patients);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!Call_PatientsExists(call_Patients.MobileNo))
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
            return View(call_Patients);
        }

        // GET: Patients/Delete/5
        public async Task<IActionResult> Delete(string id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var call_Patients = await _context.Call_Patients
                .FirstOrDefaultAsync(m => m.MobileNo == id);
            if (call_Patients == null)
            {
                return NotFound();
            }

            return View(call_Patients);
        }

        // POST: Patients/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(string id)
        {
            var call_Patients = await _context.Call_Patients.FindAsync(id);
            if (call_Patients != null)
            {
                _context.Call_Patients.Remove(call_Patients);
            }

            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool Call_PatientsExists(string id)
        {
            return _context.Call_Patients.Any(e => e.MobileNo == id);
        }
    }
}
