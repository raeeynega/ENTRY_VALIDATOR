# REDCAP VALIDATION DASHBOARD
# ===========================
#
# WHAT IS IT?
# -----------
# A web tool that checks data entered into REDCap for errors.
# It flags mistakes and shows them on a dashboard so admins can fix them.
#
#
# HOW IT WORKS
# ------------
# 1. Data gets entered into REDCap
# 2. System detects new entries (via webhook or polling)
# 3. Runs custom validation rules on the data
# 4. If errors found, they appear in the dashboard
# 5. Admins review, correct, or dismiss errors
#
#
# MAIN FEATURES
# -------------
# • Login system with different user roles
# • Choose between projects (IBD, CHAMPS, Pregnancy)
# • Dashboard showing all errors with filters
# • See who entered bad data and from which device
# • Get suggestions on how to fix errors
# • Mark errors as corrected or dismissed
# • Admin panel to manage users
#
#
# WHO USES IT
# -----------
# • Data managers - monitor data quality
# • Supervisors - review and correct errors
# • Admins - manage users and settings
#
#
# WHY USE IT
# ----------
# • Catch data entry mistakes early
# • Keep REDCap data clean and accurate
# • Track who makes errors and how to fix them
# • Reduce manual data checking
#
#
# TECH STUFF
# ----------
# • Built with Python/Flask
# • Uses SQLite database
# • Connects to REDCap via API
# • Runs in browser