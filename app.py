import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.utils import secure_filename
try:
    from authlib.integrations.flask_client import OAuth
except Exception:
    OAuth = None

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(BASE_DIR, 'templates')
static_dir = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# ==========================================
# CONFIGURATION
# ==========================================

app.secret_key = os.environ.get("SECRET_KEY", "stuco_griffin_dev_secret_2026_change_in_prod")

if os.environ.get("VERCEL"):
    UPLOAD_FOLDER = os.path.join('/tmp', 'uploads')
else:
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'pdf', 'doc', 'docx', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

# Google OAuth config (set via environment variables in Render)
app.config['GOOGLE_CLIENT_ID'] = os.environ.get("GOOGLE_CLIENT_ID", "")
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get("GOOGLE_CLIENT_SECRET", "")

# Restrict to this school domain only
ALLOWED_DOMAIN = "bjsmicschool.com"

# Dev mode: auto-enabled when Google OAuth is not configured
DEV_MODE = not (os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))

try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except Exception:
    pass


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ==========================================
# GOOGLE OAUTH SETUP
# ==========================================

google = None
if OAuth:
    try:
        oauth = OAuth(app)
        if app.config['GOOGLE_CLIENT_ID'] and app.config['GOOGLE_CLIENT_SECRET']:
            google = oauth.register(
                name='google',
                client_id=app.config['GOOGLE_CLIENT_ID'],
                client_secret=app.config['GOOGLE_CLIENT_SECRET'],
                server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                client_kwargs={
                    'scope': 'openid email profile',
                }
            )
    except Exception:
        google = None


# ==========================================
# FLASK-LOGIN & ROLE-BASED ACCESS CONTROL (RBAC)
# ==========================================

# Directory of roles and permissions (editable in the admin panel)
ACCOUNTS = {
    "270036@bjsmicschool.com": {"name": "Cellestine Zuo", "role": "President", "can_edit_updates": True},
    "270013@bjsmicschool.com": {"name": "Jerry Li", "role": "Vice President", "can_edit_updates": True},
    "28010@bjsmicschool.com": {"name": "Lucas Lee", "role": "Secretary", "can_edit_updates": True},
    "270005@bjsmicschoo.com": {"name": "Amy Feng", "role": "Treasurer", "can_edit_updates": True},
    "elena_chen@bjsmicschool.com": {"name": "Elena Chen", "role": "Teacher", "can_edit_updates": True},
    "280007@bjsmicschool.com": {"name": "Lily Goufo", "role": "Stuco Member", "can_edit_updates": False},
    "290018@bjsmicschool.com": {"name": "Sophie Sun", "role": "Stuco Member", "can_edit_updates": False},
    "290024@bjsmicschool.com": {"name": "Rocky Yang", "role": "Stuco Member", "can_edit_updates": False},
    "280024@bjsmicschool.com": {"name": "Mike Zhan", "role": "Stuco Member", "can_edit_updates": False},
    "280019@bjsmicschool.com": {"name": "Cassie Wu", "role": "Stuco Member", "can_edit_updates": False},
    "280009@bjsmicschool.com": {"name": "Hyun Lee", "role": "Stuco Member", "can_edit_updates": False},
    "27270018@bjsmicschool.com": {"name": "Camille Lv", "role": "Stuco Member", "can_edit_updates": False},
    "290010@bjsmicschool.com": {"name": "Camille Kou", "role": "Stuco Member", "can_edit_updates": False},
    "280030@bjsmicschool.com": {"name": "Connie Ho", "role": "Stuco Member", "can_edit_updates": False},
    "student@bjsmicschool.com": {"name": "Sam V.", "role": "Student", "can_edit_updates": False}
}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'
login_manager.login_message = "Please sign in with your BJSMIC school account to continue."
login_manager.login_message_category = "info"


class User(UserMixin):
    """Simple user class backed by session — no database needed."""
    def __init__(self, user_id, name, email, picture, role="Student", can_edit_updates=False):
        self.id = user_id
        self.name = name
        self.email = email
        self.picture = picture
        self.role = role
        self.can_edit_updates = can_edit_updates

    def get_id(self):
        return self.id


# Store active sessions in memory (reset on redeploy — fine for this use case)
active_users = {}

# Track which users have completed the first-login survey
survey_completed_users = set()

# Track pending event surveys per user: {user_id: [event_id, ...]}
pending_event_surveys = {}


@login_manager.user_loader
def load_user(user_id):
    return active_users.get(user_id)


# Decorator to restrict routes to specific roles
from functools import wraps
def require_role(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in allowed_roles:
                flash("🔒 Access Denied: You do not have permission to perform this action.", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ==========================================
# AUTH ROUTES
# ==========================================

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    error = request.args.get('error')
    return render_template('login.html', error=error, dev_mode=DEV_MODE)


@app.route('/auth/google')
def google_login():
    """Redirect the user to Google's OAuth consent screen."""
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri, hd=ALLOWED_DOMAIN)


@app.route('/auth/callback')
def google_callback():
    """Handle Google's OAuth callback, verify domain, and log the user in."""
    try:
        token = google.authorize_access_token()
    except Exception:
        return redirect(url_for('login_page', error="Authentication failed. Please try again."))

    user_info = token.get('userinfo')
    if not user_info:
        return redirect(url_for('login_page', error="Could not retrieve account info from Google."))

    email = user_info.get('email', '')
    domain = email.split('@')[-1] if '@' in email else ''

    # Domain restriction — only @bjsmicschool.com allowed
    if domain.lower() != ALLOWED_DOMAIN:
        return redirect(url_for('login_page',
            error=f"Access denied. Only @{ALLOWED_DOMAIN} accounts are allowed. "
                  f"You signed in with: {email}"))

    # Fetch role and permissions from ACCOUNTS directory, defaulting to Student
    account_info = ACCOUNTS.get(email.lower(), {"name": user_info.get('name', email.split('@')[0]), "role": "Student", "can_edit_updates": False})
    
    # Create or update user
    user_id = user_info.get('sub')  # Google's stable unique ID
    user = User(
        user_id=user_id,
        name=account_info["name"],
        email=email,
        picture=user_info.get('picture', ''),
        role=account_info["role"],
        can_edit_updates=account_info["can_edit_updates"]
    )
    active_users[user_id] = user
    login_user(user, remember=True)

    # If this user hasn't completed the first-login survey, send them there
    if user_id not in survey_completed_users:
        return redirect(url_for('survey_page'))

    # Check for pending event survey
    if user_id in pending_event_surveys and pending_event_surveys[user_id]:
        event_id = pending_event_surveys[user_id][0]
        return redirect(url_for('survey_page', survey_type='event', event_id=event_id))

    # Redirect to the page they originally tried to visit, or home
    next_page = request.args.get('next') or url_for('home')
    return redirect(next_page)


@app.route('/logout')
@login_required
def logout():
    active_users.pop(current_user.id, None)
    logout_user()
    return redirect(url_for('login_page'))


@app.route('/dev-login')
def dev_login():
    """Dev-only bypass supporting multiple roles. Disabled when Google credentials are set."""
    if not DEV_MODE:
        return redirect(url_for('login_page'))
    
    email = request.args.get('email', 'president@bjsmicschool.com').lower()
    account_info = ACCOUNTS.get(email)
    if not account_info:
        return redirect(url_for('login_page', error="Selected dev account does not exist."))

    user_id = f"dev-user-{email.split('@')[0]}"
    user = User(
        user_id=user_id,
        name=account_info["name"],
        email=email,
        picture="",
        role=account_info["role"],
        can_edit_updates=account_info["can_edit_updates"]
    )
    active_users[user_id] = user
    login_user(user, remember=True)
    # Skip survey for dev users to make testing faster
    survey_completed_users.add(user_id)
    return redirect(url_for('home'))




# ==========================================
# MOCK DATA STORES
# ==========================================

ANNOUNCEMENTS = [
    {
        "id": 1,
        "title": "Welcome Back to the Main Campus!",
        "date": "August 7, 2026",
        "badge": "Important Update",
        "badge_color": "priority",
        "content": "Stuco is thrilled to welcome everyone back to the main campus! Check out our new event calendar and stay tuned for main courtyard pep rally announcements.",
        "link": "/calendar",
        "link_text": "View Campus Calendar →"
    },
    {
        "id": 2,
        "title": "Homecoming 2026 Ticket Presale Open",
        "date": "August 5, 2026",
        "badge": "Tickets & RSVPs",
        "badge_color": "event",
        "content": "Early bird tickets for 'Homecoming 2026' are now live. Reserve your spot before prices increase next month.",
        "link": "/calendar",
        "link_text": "Book Tickets Now →"
    },
    {
        "id": 3,
        "title": "Main Campus Vending Machine Suggestions",
        "date": "August 3, 2026",
        "badge": "Student Voice",
        "badge_color": "community",
        "content": "Have a snack or drink you want stocked in the main campus vending machines? Submit your requests directly to our Vending Committee.",
        "link": "/vending",
        "link_text": "Submit Snack Request →"
    }
]

STUCO_MEMBERS = [
    {
        "name": "Cellestine Zuo",
        "role": "Student Body President",
        "grade": "Senior (Class of '27)",
        "quote": "Leading our return to the main campus with transparency, enthusiasm, and unstoppable Griffin spirit!",
        "email": "270036@bjsmicschool.com"
    },
    {
        "name": "Jerry Li",
        "role": "Vice President",
        "grade": "Senior (Class of '27)",
        "quote": "Coordinating student life activities and serving as the direct channel between student voices and administration.",
        "email": "270013@bjsmicschool.com"
    },
    {
        "name": "Lucas Lee",
        "role": "Secretary",
        "grade": "Junior (Class of '28)",
        "quote": "Managing documentations, maintaining schedules, and keeping student leaders fully synchronized.",
        "email": "28010@bjsmicschool.com"
    },
    {
        "name": "Amy Feng",
        "role": "Student Body Treasurer",
        "grade": "Senior (Class of '27)",
        "quote": "Allocating funds fairly across events and maintaining a transparent budget for all student activities.",
        "email": "270005@bjsmicschoo.com"
    },
    {
        "name": "Lily Goufo",
        "role": "Activity Officer",
        "grade": "Junior (Class of '28)",
        "quote": "Organizing school dances, spirit rallies, and campus festivals to build our Griffin community.",
        "email": "280007@bjsmicschool.com"
    },
    {
        "name": "Sophie Sun",
        "role": "Media Officer",
        "grade": "Sophomore (Class of '29)",
        "quote": "Documenting school memories through photos, recap videos, and dynamic visuals.",
        "email": "290018@bjsmicschool.com"
    },
    {
        "name": "Rocky Yang",
        "role": "Publicity Officer",
        "grade": "Sophomore (Class of '29)",
        "quote": "Designing flyers, managing social channels, and publicizing all upcoming student activities.",
        "email": "290024@bjsmicschool.com"
    },
    {
        "name": "Mike Zhan",
        "role": "Chief Technology Officer",
        "grade": "Junior (Class of '28)",
        "quote": "Developing digital tools, maintaining the Stuco site, and managing systems integration.",
        "email": "280024@bjsmicschool.com"
    },
    {
        "name": "Cassie Wu",
        "role": "Red House Leader",
        "grade": "Junior (Class of '28)",
        "quote": "Fostering collaboration, leading sports meets, and driving Red House to victory!",
        "email": "280019@bjsmicschool.com"
    },
    {
        "name": "Hyun Lee",
        "role": "Green House Leader",
        "grade": "Junior (Class of '28)",
        "quote": "Bringing green house pride to pep rallies, sports days, and academic challenge basins.",
        "email": "280009@bjsmicschool.com"
    },
    {
        "name": "Camille Lv",
        "role": "Yellow House Leader",
        "grade": "Senior (Class of '27)",
        "quote": "Powering Yellow House to first place with high energy, house events, and friendly competition.",
        "email": "27270018@bjsmicschool.com"
    },
    {
        "name": "Camille Kou",
        "role": "Blue House Leader",
        "grade": "Sophomore (Class of '29)",
        "quote": "Inspiring blue house solidarity, support, and excellence in every student-led tournament.",
        "email": "290010@bjsmicschool.com"
    },
    {
        "name": "Connie Ho",
        "role": "Charity Officer",
        "grade": "Junior (Class of '28)",
        "quote": "Dedicated to organizing donation drives, volunteering campaigns, and community service projects to make a difference.",
        "email": "280030@bjsmicschool.com"
    }
]

EVENTS = {
    1: {
        "id": 1,
        "title": "Homecoming Dance 2026",
        "date": "2026-10-24",
        "display_date": "Saturday, October 24, 2026",
        "time": "7:00 PM - 10:30 PM",
        "location": "Main Gymnasium & Courtyard",
        "category": "Paid Event",
        "scope": "Entire School",
        "requires_booking": True,
        "participants": [
            {"id": 1, "name": "Sam V.", "grade": "12", "email": "student@bjsmicschool.com", "status": "Confirmed"},
            {"id": 2, "name": "Jerry Li", "grade": "12", "email": "270013@bjsmicschool.com", "status": "Pending"}
        ],
        "lead": "Cellestine (Stuco President)",
        "budget_allocated": "$2,500.00",
        "description": "Annual homecoming dance setup on the main campus. Theme and decor layout pending final approval.",
        "ticket_link": "https://schooltickets.example.com/homecoming",
        "ticket_status": "Tickets Available ($15)",
        "has_workspace": True,
        "schedule": [
            {"time": "7:00 PM", "activity": "Doors Open & Photo Booths"},
            {"time": "8:30 PM", "activity": "Royalty Crowning Ceremony"},
            {"time": "9:30 PM", "activity": "Special Griffin Mascot Dance Off"},
            {"time": "10:30 PM", "activity": "Event Concludes"}
        ],
        "tasks": [
            {"id": 101, "date": "2026-10-01", "task": "Finalize DJ Contract", "assignee": "Alex M.", "details": "Review and sign the contract with DJ Griffin", "notes": "Approved by Advisor", "status": "In Progress"},
            {"id": 102, "date": "2026-10-05", "task": "Confirm Gymnasium Floor Coverings", "assignee": "Jordan K.", "details": "Check inventory for protective tarp rolls", "notes": "Need to verify tape quantity", "status": "To Do"},
            {"id": 103, "date": "2026-09-28", "task": "Design Ticket Flyers & Social Graphics", "assignee": "Taylor S.", "details": "Create Canva assets and share with PR team", "notes": "Flyers printed!", "status": "Completed"}
        ],
        "photos": []
    },
    2: {
        "id": 2,
        "title": "Main Campus Welcome Pep Rally",
        "date": "2026-08-28",
        "display_date": "Friday, August 28, 2026",
        "time": "1:30 PM - 3:00 PM",
        "location": "Central Courtyard",
        "category": "Free School Event",
        "scope": "Entire School",
        "requires_booking": False,
        "participants": [],
        "lead": "Jordan K. (Logistics Lead)",
        "budget_allocated": "$350.00",
        "description": "Kickoff pep rally introducing all Stuco committees, school mascot performance, and class competitions.",
        "ticket_link": "",
        "ticket_status": "Free Entry",
        "has_workspace": True,
        "schedule": [
            {"time": "1:30 PM", "activity": "Griffin Mascot Entrance & Marching Band"},
            {"time": "2:00 PM", "activity": "Class Tug-of-War Competition"},
            {"time": "2:45 PM", "activity": "Presidential Welcome Address & Free Popsicles"}
        ],
        "tasks": [
            {"id": 201, "date": "2026-08-15", "task": "Rent ice cream coolers", "assignee": "Jordan K.", "details": "Source 3 coolers for popsicles", "notes": "Popsicles sponsored", "status": "To Do"},
            {"id": 202, "date": "2026-08-20", "task": "Invite Marching Band", "assignee": "Taylor S.", "details": "Send invitation letter to Band Director", "notes": "Awaiting response", "status": "In Progress"}
        ],
        "photos": []
    },
    3: {
        "id": 3,
        "title": "Fall Club Rush & Food Fair",
        "date": "2026-09-15",
        "display_date": "Tuesday, September 15, 2026",
        "time": "12:00 PM - 2:00 PM",
        "location": "Main Campus Plaza",
        "category": "Free School Event",
        "scope": "High School",
        "requires_booking": False,
        "participants": [],
        "lead": "Alex M. (Vice President)",
        "budget_allocated": "$500.00",
        "description": "Explore 30+ student organizations, sign up for campus committees, and enjoy food stalls managed by Stuco.",
        "ticket_link": "",
        "ticket_status": "Free Entry",
        "has_workspace": True,
        "schedule": [
            {"time": "12:00 PM", "activity": "Club Booths & Food Stalls Open"},
            {"time": "1:00 PM", "activity": "Acoustic Stage Performances"}
        ],
        "tasks": [
            {"id": 301, "date": "2026-09-01", "task": "Print layout map", "assignee": "Alex M.", "details": "Draft map of booth spacing in main courtyard", "notes": "Need to count clubs first", "status": "To Do"}
        ],
        "photos": []
    }
}

MEETINGS = [
    {
        "id": 1,
        "title": "Main Campus Venue Logistics & Transition",
        "date": "2026-08-12",
        "time": "3:30 PM - 4:30 PM",
        "location": "Room 204 (Stuco HQ)",
        "status": "Upcoming",
        "leader": "Cellestine (President)",
        "agenda_summary": "Review main campus venue booking rules, budget allocation for Homecoming, and Spirit Rally scheduling.",
        "agenda_file": "",
        "notes": "",
        "action_items": [
            {"task": "Draft facility request form for Gymnasium", "assignee": "Jordan K.", "done": False},
            {"task": "Confirm Griffin Mascot performer schedule", "assignee": "Taylor S.", "done": False}
        ]
    },
    {
        "id": 2,
        "title": "Executive Council Orientation & Fall Calendar",
        "date": "2026-08-01",
        "time": "2:00 PM - 3:30 PM",
        "location": "Student Center Conference Room",
        "status": "Archived",
        "leader": "Cellestine (President)",
        "agenda_summary": "Finalize fall semester goal priorities, committee budget limits, and main campus transition strategy.",
        "agenda_file": "",
        "notes": "1. Approved $2,500 baseline budget for Homecoming 2026.\n2. Vending machine suggestion portal approved for Stuco site.\n3. Weekly meetings set for Wednesdays at 3:30 PM.",
        "action_items": [
            {"task": "Set up Python Stuco Web Portal", "assignee": "Tech Lead", "done": True},
            {"task": "Distribute committee signup forms", "assignee": "Alex M.", "done": True}
        ]
    }
]

BUDGET_REQUESTS = [
    {
        "id": 101,
        "event_title": "Homecoming Dance 2026",
        "committee": "Decor & Spirit",
        "requester": "Taylor S.",
        "amount": 285.50,
        "category": "Decorations",
        "item_description": "Griffin Mascot Photo Arch Balloons & Blue Drape Fabric",
        "justification": "Required for main entrance photo booth backdrop on main campus.",
        "attachment": "",
        "status": "Approved",
        "treasurer_notes": "Approved under Homecoming Decor Line Item #4.",
        "date_submitted": "2026-08-05"
    },
    {
        "id": 102,
        "event_title": "Fall Spirit Week",
        "committee": "Logistics",
        "requester": "Jordan K.",
        "amount": 120.00,
        "category": "Equipment",
        "item_description": "Outdoor Portable Megaphone and Batteries",
        "justification": "Needed for crowd control during courtyard pep rallies.",
        "attachment": "",
        "status": "Pending",
        "treasurer_notes": "",
        "date_submitted": "2026-08-06"
    },
    {
        "id": 103,
        "event_title": "General Stuco HQ",
        "committee": "Executive",
        "requester": "Alex M.",
        "amount": 45.00,
        "category": "Supplies",
        "item_description": "Dry erase markers and whiteboard calendar grid",
        "justification": "Planning calendar for Room 204 HQ transition.",
        "attachment": "",
        "status": "Reimbursed",
        "treasurer_notes": "Reimbursed via school check #8421.",
        "date_submitted": "2026-08-02"
    }
]

VENDING_ITEMS = [
    {
        "id": 1,
        "name": "Baked Jalapeño Chips",
        "category": "Snacks",
        "price": 1.75,
        "status": "In Stock",
        "badge": "Popular",
        "icon": "🍿",
        "description": "Crunchy spicy baked potato chips. Located in Main Hall Machine #1."
    },
    {
        "id": 2,
        "name": "Sparkling Berry Electrolyte Water",
        "category": "Drinks",
        "price": 2.25,
        "status": "Just Restocked!",
        "badge": "New Arrival",
        "icon": "🥤",
        "description": "Zero sugar berry refreshment. Main Courtyard Machine."
    }
]

VENDING_SUGGESTIONS = [
    {
        "id": 1,
        "item_name": "Matcha Boba Milk Tea (Canned)",
        "category": "Drinks",
        "suggested_by": "Sam V. (Senior)",
        "reason": "Perfect afternoon pick-me-up during AP study sessions!",
        "votes": 42,
        "status": "Under Review"
    }
]

STUCO_DEBT = "¥0.00"
STUCO_BALANCE = "¥15,000.00"

INVENTORY = [
    {
        "id": 1,
        "name": "Portable Megaphone & Speakers",
        "quantity": 2,
        "location": "Shelf A - Box 3",
        "condition": "Good",
        "notes": "Used for pep rallies and courtyard events.",
        "picture": ""
    },
    {
        "id": 2,
        "name": "Griffin Mascot Costume",
        "quantity": 1,
        "location": "Main Closet",
        "condition": "Excellent",
        "notes": "Dry cleaned after Homecoming 2025.",
        "picture": ""
    },
    {
        "id": 3,
        "name": "Blue & Gold Drape Fabrics",
        "quantity": 15,
        "location": "Shelf B - Box 1",
        "condition": "Good",
        "notes": "For stage background decoration.",
        "picture": ""
    }
]


# ==========================================
# DATA PERSISTENCE (JSON BACKING STORE)
# ==========================================

DATA_DIR = os.path.join('/tmp', 'data') if os.environ.get("VERCEL") else os.path.join(BASE_DIR, 'data')
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except Exception:
    pass
DATA_FILE = os.path.join(DATA_DIR, 'store.json')

def save_data():
    try:
        store = {
            "ACCOUNTS": ACCOUNTS,
            "STUCO_MEMBERS": STUCO_MEMBERS,
            "EVENTS": EVENTS,
            "MEETINGS": MEETINGS,
            "ANNOUNCEMENTS": ANNOUNCEMENTS,
            "BUDGET_REQUESTS": BUDGET_REQUESTS,
            "VENDING_ITEMS": VENDING_ITEMS,
            "VENDING_SUGGESTIONS": VENDING_SUGGESTIONS,
            "VOLUNTEER_OPPORTUNITIES": VOLUNTEER_OPPORTUNITIES,
            "STUCO_DEBT": STUCO_DEBT,
            "STUCO_BALANCE": STUCO_BALANCE,
            "INVENTORY": INVENTORY
        }
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(store, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Error saving data: {e}")

def load_data():
    global ACCOUNTS, STUCO_MEMBERS, EVENTS, MEETINGS, ANNOUNCEMENTS, BUDGET_REQUESTS, VENDING_ITEMS, VENDING_SUGGESTIONS, VOLUNTEER_OPPORTUNITIES, STUCO_DEBT, STUCO_BALANCE, INVENTORY
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                store = json.load(f)
                if "ACCOUNTS" in store: ACCOUNTS = store["ACCOUNTS"]
                if "STUCO_MEMBERS" in store: STUCO_MEMBERS = store["STUCO_MEMBERS"]
                if "EVENTS" in store:
                    EVENTS = {int(k): v for k, v in store["EVENTS"].items()}
                if "MEETINGS" in store: MEETINGS = store["MEETINGS"]
                if "ANNOUNCEMENTS" in store: ANNOUNCEMENTS = store["ANNOUNCEMENTS"]
                if "BUDGET_REQUESTS" in store: BUDGET_REQUESTS = store["BUDGET_REQUESTS"]
                if "VENDING_ITEMS" in store: VENDING_ITEMS = store["VENDING_ITEMS"]
                if "VENDING_SUGGESTIONS" in store: VENDING_SUGGESTIONS = store["VENDING_SUGGESTIONS"]
                if "VOLUNTEER_OPPORTUNITIES" in store: VOLUNTEER_OPPORTUNITIES = store["VOLUNTEER_OPPORTUNITIES"]
                if "STUCO_DEBT" in store: STUCO_DEBT = store["STUCO_DEBT"]
                if "STUCO_BALANCE" in store: STUCO_BALANCE = store["STUCO_BALANCE"]
                if "INVENTORY" in store: INVENTORY = store["INVENTORY"]
        except Exception as e:
            print(f"Error loading data: {e}")

load_data()


# ==========================================
# CONTEXT PROCESSOR — inject user into all templates
# ==========================================

@app.context_processor
def inject_user():
    return dict(current_user=current_user)


# ==========================================
# ROUTE HANDLERS
# ==========================================

# 1. Main Landing Page
@app.route('/')
@login_required
def home():
    all_events = list(EVENTS.values())
    upcoming_events = sorted(all_events, key=lambda x: x.get('date', ''))[:2]
    return render_template('index.html', announcements=ANNOUNCEMENTS, members=STUCO_MEMBERS, upcoming_events=upcoming_events, events=all_events)


# 2. Public Event Calendar & API — no login needed
@app.route('/calendar')
def public_calendar():
    return render_template('calendar.html', events=list(EVENTS.values()))



@app.route('/api/events/<int:event_id>')
def get_event_details(event_id):

    event = EVENTS.get(event_id)
    if event:
        return jsonify(event)
    return jsonify({"error": "Event not found"}), 404


# 3. Event Workspace — public view, login required to edit
@app.route('/workspace')
@app.route('/workspace/<int:event_id>')
def event_workspace(event_id=1):
    event = EVENTS.get(event_id)
    if not event:
        event_id = 1
        event = EVENTS.get(1)

    if "purchases" not in event:
        event["purchases"] = []

    raw_budget_str = event.get("budget_allocated", "¥0").replace('¥', '').replace('$', '').replace(',', '').strip()
    try:
        total_budget = float(raw_budget_str)
    except ValueError:
        total_budget = 0.0

    total_spent = sum(float(p.get("cost", 0)) for p in event["purchases"])
    remaining_budget = total_budget - total_spent

    # Budget Plan summaries across all events
    event_budgets = []
    grand_total_allocated = 0.0
    grand_total_spent = 0.0

    for eid, ev in EVENTS.items():
        b_str = ev.get("budget_allocated", "¥0").replace('¥', '').replace('$', '').replace(',', '').strip()
        try: b_tot = float(b_str)
        except ValueError: b_tot = 0.0
        p_list = ev.get("purchases", [])
        s_tot = sum(float(p.get("cost", 0)) for p in p_list)
        grand_total_allocated += b_tot
        grand_total_spent += s_tot
        event_budgets.append({
            "id": eid,
            "title": ev.get("title"),
            "category": ev.get("category"),
            "display_date": ev.get("display_date"),
            "total_budget": b_tot,
            "total_spent": s_tot,
            "remaining": b_tot - s_tot,
            "purchases": p_list
        })

    # All tasks arranged by due date
    all_tasks = []
    for eid, ev in EVENTS.items():
        for t in ev.get("tasks", []):
            all_tasks.append({
                "date": t.get("date", "9999-99-99"),
                "task": t.get("task"),
                "assignee": t.get("assignee", "Unassigned"),
                "event_title": ev.get("title"),
                "event_id": eid,
                "status": t.get("status", "To Do"),
                "notes": t.get("notes", "")
            })
    for m in MEETINGS:
        for item in m.get("action_items", []):
            all_tasks.append({
                "date": m.get("date", "9999-99-99"),
                "task": item.get("task"),
                "assignee": item.get("assignee", "Unassigned"),
                "event_title": item.get("event_title") or f"Meeting: {m.get('title')}",
                "event_id": item.get("event_id") or 1,
                "status": "Completed" if item.get("done") else "To Do",
                "notes": "Action item from meeting"
            })
            
    all_tasks_sorted = sorted(all_tasks, key=lambda x: x.get("date", "9999-99-99"))

    return render_template(
        'workspace.html',
        event=event,
        events=list(EVENTS.values()),
        total_budget=total_budget,
        total_spent=total_spent,
        remaining_budget=remaining_budget,
        event_budgets=event_budgets,
        grand_total_allocated=grand_total_allocated,
        grand_total_spent=grand_total_spent,
        grand_remaining=grand_total_allocated - grand_total_spent,
        stuco_debit=STUCO_DEBT,
        stuco_balance=STUCO_BALANCE,
        all_tasks_sorted=all_tasks_sorted,
        inventory=INVENTORY
    )


@app.route('/inventory/add', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def add_inventory_item():
    name = request.form.get('name', '').strip()
    quantity = _safe_int(request.form.get('quantity'), 1)
    location = request.form.get('location', '').strip()
    condition = request.form.get('condition', 'Good').strip()
    notes = request.form.get('notes', '').strip()
    
    file = request.files.get('picture_file')
    picture_url = request.form.get('picture_url', '').strip()
    picture_src = ""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        picture_src = url_for('static', filename='uploads/' + filename)
    elif picture_url:
        picture_src = picture_url

    new_id = max([i['id'] for i in INVENTORY], default=0) + 1
    INVENTORY.append({
        "id": new_id,
        "name": name,
        "quantity": quantity,
        "location": location,
        "condition": condition,
        "notes": notes,
        "picture": picture_src
    })
    save_data()
    flash(f"Storage item '{name}' logged into inventory!", "success")
    return redirect(url_for('event_workspace', event_id=1))


@app.route('/inventory/delete/<int:item_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def delete_inventory_item(item_id):
    global INVENTORY
    INVENTORY = [i for i in INVENTORY if i['id'] != item_id]
    save_data()
    flash("Storage item removed from inventory.", "success")
    return redirect(url_for('event_workspace', event_id=1))


@app.route('/inventory/edit/<int:item_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def edit_inventory_item(item_id):
    item = next((i for i in INVENTORY if i['id'] == item_id), None)
    if item:
        item['name'] = request.form.get('name', item['name']).strip()
        item['quantity'] = _safe_int(request.form.get('quantity'), item['quantity'])
        item['location'] = request.form.get('location', item['location']).strip()
        item['condition'] = request.form.get('condition', item['condition']).strip()
        item['notes'] = request.form.get('notes', item['notes']).strip()
        
        file = request.files.get('picture_file')
        picture_url = request.form.get('picture_url', '').strip()
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            item['picture'] = url_for('static', filename='uploads/' + filename)
        elif picture_url:
            item['picture'] = picture_url
            
        save_data()
        flash(f"Storage item '{item['name']}' updated successfully!", "success")
    return redirect(url_for('event_workspace', event_id=1))


@app.route('/workspace/<int:event_id>/edit_budget', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Teacher'])
def edit_event_budget(event_id):
    event = EVENTS.get(event_id)
    if event:
        val = request.form.get('budget_allocated', '').strip()
        val_clean = val.replace('¥', '').replace('$', '').replace(',', '').strip()
        event['budget_allocated'] = f"¥{val_clean}" if val_clean else "¥0.00"
        save_data()
        flash(f"Budget limit for '{event['title']}' updated to {event['budget_allocated']}!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/add_row', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def add_workspace_row(event_id):
    event = EVENTS.get(event_id)
    if event:
        date = request.form.get('date', '')
        task = request.form.get('task', '')
        assignee = request.form.get('assignee', '')
        details = request.form.get('details', '')
        notes = request.form.get('notes', '')
        status = request.form.get('status', 'To Do')
        
        new_row = {
            "id": len(event.get("tasks", [])) + 101,
            "date": date,
            "task": task,
            "assignee": assignee,
            "details": details,
            "notes": notes,
            "status": status
        }
        if "tasks" not in event:
            event["tasks"] = []
        event["tasks"].append(new_row)
        flash("Timeline row added successfully!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/edit_row/<int:row_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def edit_workspace_row(event_id, row_id):
    event = EVENTS.get(event_id)
    if event:
        for r in event.get("tasks", []):
            if r["id"] == row_id:
                r["date"] = request.form.get('date', r["date"])
                r["task"] = request.form.get('task', r["task"])
                r["assignee"] = request.form.get('assignee', r["assignee"])
                r["details"] = request.form.get('details', r["details"])
                r["notes"] = request.form.get('notes', r["notes"])
                r["status"] = request.form.get('status', r["status"])
                flash("Timeline row updated successfully!", "success")
                break
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/delete_row/<int:row_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def delete_workspace_row(event_id, row_id):
    event = EVENTS.get(event_id)
    if event:
        event["tasks"] = [r for r in event.get("tasks", []) if r["id"] != row_id]
        flash("Timeline row deleted successfully!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/add_participant', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def add_participant(event_id):
    event = EVENTS.get(event_id)
    if event:
        name = request.form.get('name', '').strip()
        grade = request.form.get('grade', '').strip()
        email = request.form.get('email', '').strip()
        status = request.form.get('status', 'Confirmed').strip()
        
        if "participants" not in event:
            event["participants"] = []
            
        new_id = max([p['id'] for p in event["participants"]], default=0) + 1
        
        event["participants"].append({
            "id": new_id,
            "name": name,
            "grade": grade,
            "email": email,
            "status": status
        })
        flash(f"Student '{name}' added to participating list!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/edit_participant/<int:part_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def edit_participant(event_id, part_id):
    event = EVENTS.get(event_id)
    if event:
        for p in event.get("participants", []):
            if p["id"] == part_id:
                p["name"] = request.form.get('name', p["name"])
                p["grade"] = request.form.get('grade', p["grade"])
                p["email"] = request.form.get('email', p["email"])
                p["status"] = request.form.get('status', p["status"])
                flash(f"Participant details updated successfully!", "success")
                break
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/delete_participant/<int:part_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def delete_participant(event_id, part_id):
    event = EVENTS.get(event_id)
    if event:
        event["participants"] = [p for p in event.get("participants", []) if p["id"] != part_id]
        flash("Participant removed successfully!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/add_purchase', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def add_purchase(event_id):
    event = EVENTS.get(event_id)
    if event:
        item = request.form.get('item', '').strip()
        try:
            cost = float(request.form.get('cost', '0.0'))
        except ValueError:
            cost = 0.0
        buyer = request.form.get('buyer', '').strip() or current_user.name
        date = request.form.get('date', '').strip()
        notes = request.form.get('notes', '').strip()

        if "purchases" not in event:
            event["purchases"] = []

        new_id = max([p['id'] for p in event["purchases"]], default=0) + 1
        event["purchases"].append({
            "id": new_id,
            "item": item,
            "cost": cost,
            "buyer": buyer,
            "date": date,
            "notes": notes
        })
        flash(f"Purchased item '{item}' logged under event budget!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/delete_purchase/<int:purchase_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def delete_purchase(event_id, purchase_id):
    event = EVENTS.get(event_id)
    if event:
        event["purchases"] = [p for p in event.get("purchases", []) if p["id"] != purchase_id]
        flash("Purchased item record removed.", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


@app.route('/workspace/<int:event_id>/upload_photo', methods=['POST'])
@login_required
def upload_photo(event_id):
    event = EVENTS.get(event_id)
    if event and 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            event["photos"].append({
                "filename": filename,
                "caption": request.form.get('caption', filename),
                "category": request.form.get('category', 'Venue Photo')
            })
            flash("Image uploaded to workspace gallery!", "success")
    return redirect(url_for('event_workspace', event_id=event_id))


# 4. Meetings Hub — public view, login required to edit
@app.route('/meetings')
def meetings_hub():
    return render_template('meetings.html', meetings=MEETINGS, events=list(EVENTS.values()))


@app.route('/meetings/add', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary'])
def add_meeting():
    file = request.files.get('agenda_file')
    filename = ""
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    new_id = max([m['id'] for m in MEETINGS], default=0) + 1
    MEETINGS.insert(0, {
        "id": new_id,
        "title": request.form.get('title'),
        "date": request.form.get('date'),
        "time": request.form.get('time', 'TBD'),
        "location": request.form.get('location', 'Room 204'),
        "status": "Upcoming",
        "leader": request.form.get('leader', 'Stuco Exec'),
        "agenda_summary": request.form.get('agenda_summary', 'No summary provided.'),
        "agenda_file": filename,
        "notes": "",
        "action_items": []
    })
    flash("Meeting and agenda published!", "success")
    return redirect(url_for('meetings_hub'))


@app.route('/meetings/<int:meeting_id>/update_notes', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher', 'Stuco Member'])
def update_meeting_notes(meeting_id):
    meeting = next((m for m in MEETINGS if m['id'] == meeting_id), None)
    if meeting:
        meeting['notes'] = request.form.get('notes', '')
        meeting['status'] = request.form.get('status', meeting['status'])
        new_task = request.form.get('new_task', '').strip()
        
        if new_task:
            assignee = request.form.get('task_assignee', 'Unassigned').strip()
            target_event_id_str = request.form.get('target_event_id', '').strip()
            
            event_id = None
            event_title = None
            
            if target_event_id_str.isdigit():
                event_id = int(target_event_id_str)
                target_event = EVENTS.get(event_id)
                if target_event:
                    event_title = target_event.get("title")
                    # Add task row to event workspace automatically
                    new_row_id = max([r['id'] for r in target_event.get("tasks", [])], default=100) + 1
                    if "tasks" not in target_event:
                        target_event["tasks"] = []
                    target_event["tasks"].append({
                        "id": new_row_id,
                        "date": meeting.get("date", "Pre-event"),
                        "task": new_task,
                        "assignee": assignee,
                        "details": f"From Meeting: {meeting['title']}",
                        "notes": f"Action item created in meeting on {meeting.get('date')}",
                        "status": "To Do"
                    })
                    flash(f"Action item '{new_task}' synced to workspace for '{event_title}'!", "success")

            meeting['action_items'].append({
                "task": new_task,
                "assignee": assignee,
                "event_id": event_id,
                "event_title": event_title,
                "done": False
            })
            if not event_title:
                flash("Meeting notes and action item saved!", "success")
        else:
            flash("Meeting notes updated!", "success")
            
    return redirect(url_for('meetings_hub'))


# 5. Budget Plan (Treasurer Portal) — Event-Specific Budget Overview & Stuco Finances
@app.route('/budget')
@login_required
def budget_portal():
    event_budgets = []
    grand_total_allocated = 0.0
    grand_total_spent = 0.0

    for event_id, event in EVENTS.items():
        raw_budget_str = event.get("budget_allocated", "¥0").replace('¥', '').replace('$', '').replace(',', '').strip()
        try:
            total_budget = float(raw_budget_str)
        except ValueError:
            total_budget = 0.0

        purchases = event.get("purchases", [])
        total_spent = sum(float(p.get("cost", 0)) for p in purchases)
        remaining = total_budget - total_spent

        grand_total_allocated += total_budget
        grand_total_spent += total_spent

        event_budgets.append({
            "id": event_id,
            "title": event.get("title"),
            "category": event.get("category"),
            "display_date": event.get("display_date"),
            "total_budget": total_budget,
            "total_spent": total_spent,
            "remaining": remaining,
            "purchases": purchases
        })

    return render_template(
        'budget.html',
        events=event_budgets,
        grand_total_allocated=grand_total_allocated,
        grand_total_spent=grand_total_spent,
        grand_remaining=grand_total_allocated - grand_total_spent,
        stuco_debit=STUCO_DEBT,
        stuco_balance=STUCO_BALANCE
    )


@app.route('/budget/edit_balance', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Treasurer'])
def edit_stuco_balance():
    global STUCO_BALANCE, STUCO_DEBT
    balance = request.form.get('balance', '').strip()
    debt = request.form.get('debt', '').strip()
    
    if balance:
        bal_clean = balance.replace('¥', '').replace('$', '').replace(',', '').strip()
        STUCO_BALANCE = f"¥{bal_clean}" if bal_clean else "¥0.00"
    if debt:
        debt_clean = debt.replace('¥', '').replace('$', '').replace(',', '').strip()
        STUCO_DEBT = f"¥{debt_clean}" if debt_clean else "¥0.00"
        
    save_data()
    flash("Stuco Treasury Balance & Debit updated successfully!", "success")
    return redirect(url_for('budget_portal'))


@app.route('/budget/submit', methods=['POST'])
@login_required
def submit_budget_request():
    filename = ""
    if 'attachment' in request.files:
        file = request.files['attachment']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    new_id = max([r['id'] for r in BUDGET_REQUESTS], default=100) + 1
    BUDGET_REQUESTS.insert(0, {
        "id": new_id,
        "event_title": request.form.get('event_title', 'General Event'),
        "committee": request.form.get('committee', 'General'),
        "requester": request.form.get('requester', current_user.name),
        "amount": float(request.form.get('amount', 0.0)),
        "category": request.form.get('category', 'Miscellaneous'),
        "item_description": request.form.get('item_description'),
        "justification": request.form.get('justification', 'N/A'),
        "attachment": filename,
        "status": "Pending",
        "treasurer_notes": "",
        "date_submitted": "2026-08-07"
    })
    flash("Budget request submitted to Treasurer!", "success")
    return redirect(url_for('budget_portal'))


@app.route('/budget/<int:req_id>/review', methods=['POST'])
@login_required
def review_budget_request(req_id):
    req_item = next((r for r in BUDGET_REQUESTS if r['id'] == req_id), None)
    if req_item:
        req_item['status'] = request.form.get('status', req_item['status'])
        req_item['treasurer_notes'] = request.form.get('treasurer_notes', '')
        flash(f"Request #{req_id} status updated to {req_item['status']}", "success")
    return redirect(url_for('budget_portal'))


# 6. Vending Machine Hub & Student Suggestions
@app.route('/vending')
@login_required
def vending_hub():
    sorted_sug = sorted(VENDING_SUGGESTIONS, key=lambda x: x['votes'], reverse=True)
    return render_template('vending.html', items=VENDING_ITEMS, suggestions=sorted_sug)


@app.route('/vending/suggest', methods=['POST'])
@login_required
def submit_vending_suggestion():
    item_name = request.form.get('item_name')
    if item_name:
        new_id = max([s['id'] for s in VENDING_SUGGESTIONS], default=0) + 1
        VENDING_SUGGESTIONS.append({
            "id": new_id,
            "item_name": item_name,
            "category": request.form.get('category', 'Snacks'),
            "suggested_by": "Anonymous",
            "reason": "",
            "votes": 1,
            "status": "Under Review"
        })
        flash("Snack suggestion submitted!", "success")
    return redirect(url_for('vending_hub'))


@app.route('/vending/vote/<int:suggestion_id>', methods=['POST'])
@login_required
def vote_suggestion(suggestion_id):
    sug = next((s for s in VENDING_SUGGESTIONS if s['id'] == suggestion_id), None)
    if sug:
        sug['votes'] += 1
        flash(f"Voted for {sug['item_name']}!", "success")
    return redirect(url_for('vending_hub'))


@app.route('/vending/add', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def add_vending_item():
    name = request.form.get('name')
    if name:
        new_id = max([i['id'] for i in VENDING_ITEMS], default=0) + 1
        try:
            price = float(request.form.get('price', '0.0'))
        except ValueError:
            price = 0.0
        VENDING_ITEMS.append({
            "id": new_id,
            "name": name,
            "category": request.form.get('category', 'Snacks'),
            "price": price,
            "status": request.form.get('status', 'In Stock'),
            "badge": request.form.get('badge', ''),
            "icon": request.form.get('icon', '🍿'),
            "description": request.form.get('description', '')
        })
        flash(f"Vending item '{name}' added successfully!", "success")
    return redirect(url_for('vending_hub'))


@app.route('/vending/edit/<int:item_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def edit_vending_item(item_id):
    item = next((i for i in VENDING_ITEMS if i['id'] == item_id), None)
    if item:
        try:
            price = float(request.form.get('price', '0.0'))
        except ValueError:
            price = item['price']
        item['name'] = request.form.get('name', item['name'])
        item['category'] = request.form.get('category', item['category'])
        item['price'] = price
        item['status'] = request.form.get('status', item['status'])
        item['badge'] = request.form.get('badge', item['badge'])
        item['icon'] = request.form.get('icon', item['icon'])
        item['description'] = request.form.get('description', item['description'])
        flash(f"Vending item '{item['name']}' updated successfully!", "success")
    return redirect(url_for('vending_hub'))


@app.route('/vending/delete/<int:item_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Treasurer', 'Teacher', 'Stuco Member'])
def delete_vending_item(item_id):
    global VENDING_ITEMS
    VENDING_ITEMS[:] = [i for i in VENDING_ITEMS if i['id'] != item_id]
    flash("Vending item deleted successfully!", "success")
    return redirect(url_for('vending_hub'))


# ==========================================
# SURVEY & STATISTICS DATA
# ==========================================

# All submitted survey responses
SURVEY_RESPONSES = []

SEMESTER_KEYS = ['s1', 's2', 's3', 's4']
SEMESTER_LABELS = [
    'Sem 1 AY 23–24',
    'Sem 2 AY 23–24',
    'Sem 1 AY 24–25',
    'Sem 2 AY 24–25',
]


# ==========================================
# SURVEY ROUTES
# ==========================================

@app.route('/survey')
@login_required
def survey_page():
    survey_type = request.args.get('survey_type', 'first_login')
    event_id = request.args.get('event_id')
    event = EVENTS.get(int(event_id)) if event_id else None
    total_steps = 7 if survey_type == 'first_login' else 1
    return render_template(
        'survey.html',
        survey_type=survey_type,
        event=event,
        total_steps=total_steps
    )


@app.route('/survey/submit', methods=['POST'])
@login_required
def submit_survey():
    from datetime import datetime
    survey_type = request.form.get('survey_type', 'first_login')
    anonymous = request.form.get('anonymous') == 'true'

    response = {
        'id': len(SURVEY_RESPONSES) + 1,
        'user_id': current_user.id,
        'user_name': 'Anonymous' if anonymous else current_user.name,
        'user_email': '' if anonymous else current_user.email,
        'submitted_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'survey_type': survey_type,
        'committee': request.form.get('committee', ''),
        'semesters_in_stuco': request.form.get('semesters_in_stuco', ''),
        'organized_events': request.form.getlist('organized_events'),
        'nps_score': request.form.get('nps_score', ''),
        'keep_doing': request.form.get('keep_doing', ''),
        'improve': request.form.get('improve', ''),
        'open_feedback': request.form.get('open_feedback', ''),
        'overall_budget': _safe_int(request.form.get('overall_budget')),
        'overall_improvement': _safe_int(request.form.get('overall_improvement')),
    }

    if survey_type == 'first_login':
        # Collect per-semester ratings
        response['semester_ratings'] = {}
        for key in SEMESTER_KEYS:
            response['semester_ratings'][key] = {
                'overall': _safe_int(request.form.get(f'{key}_overall')),
                'events':  _safe_int(request.form.get(f'{key}_events')),
                'comms':   _safe_int(request.form.get(f'{key}_comms')),
                'team':    _safe_int(request.form.get(f'{key}_team')),
                'highlight': request.form.get(f'{key}_highlight', ''),
            }
        # Mark user as survey-complete
        survey_completed_users.add(current_user.id)

    elif survey_type == 'event':
        event_id = _safe_int(request.form.get('event_id'))
        response['event_id'] = event_id
        response['event_feedback'] = {
            'overall':    _safe_int(request.form.get('ev_overall')),
            'org':        _safe_int(request.form.get('ev_org')),
            'venue':      _safe_int(request.form.get('ev_venue')),
            'engagement': _safe_int(request.form.get('ev_engagement')),
            'best':       request.form.get('ev_best', ''),
            'improve':    request.form.get('ev_improve', ''),
        }
        # Remove pending event survey for this user
        uid = current_user.id
        if uid in pending_event_surveys and event_id in pending_event_surveys[uid]:
            pending_event_surveys[uid].remove(event_id)

    SURVEY_RESPONSES.append(response)
    flash("✅ Thank you! Your survey response has been recorded.", "success")
    return redirect(url_for('home'))


def _safe_int(val, default=0):
    """Safely convert to int, returning default if None/empty."""
    try:
        return int(val) if val else default
    except (ValueError, TypeError):
        return default


def _avg(values):
    """Return average of non-zero values, or 0."""
    vals = [v for v in values if v and v > 0]
    return round(sum(vals) / len(vals), 2) if vals else 0


# ==========================================
# STATISTICS ROUTE
# ==========================================

@app.route('/stats')
def stats_page():

    sem_responses = [r for r in SURVEY_RESPONSES if r['survey_type'] == 'first_login']
    event_responses = [r for r in SURVEY_RESPONSES if r['survey_type'] == 'event']

    # --- Semester-by-semester averages ---
    def sem_avg(key, cat):
        vals = [r['semester_ratings'][key][cat]
                for r in sem_responses
                if r.get('semester_ratings') and r['semester_ratings'][key][cat] > 0]
        return _avg(vals) if vals else 0

    overall_by_sem = [sem_avg(k, 'overall') for k in SEMESTER_KEYS]
    events_by_sem  = [sem_avg(k, 'events')  for k in SEMESTER_KEYS]
    comms_by_sem   = [sem_avg(k, 'comms')   for k in SEMESTER_KEYS]
    team_by_sem    = [sem_avg(k, 'team')    for k in SEMESTER_KEYS]

    budget_vals = [r.get('overall_budget', 0) for r in sem_responses if r.get('overall_budget', 0) > 0]
    budget_by_sem = [_avg(budget_vals)] * 4  # Single overall budget score spread across semesters

    # --- KPI totals ---
    all_overall = [r['semester_ratings'][k]['overall']
                   for r in sem_responses
                   for k in SEMESTER_KEYS
                   if r.get('semester_ratings') and r['semester_ratings'][k]['overall'] > 0]
    all_events = [r['semester_ratings'][k]['events']
                  for r in sem_responses
                  for k in SEMESTER_KEYS
                  if r.get('semester_ratings') and r['semester_ratings'][k]['events'] > 0]

    nps_vals = []
    for r in SURVEY_RESPONSES:
        try:
            nps_vals.append(int(r['nps_score']))
        except (ValueError, TypeError):
            pass

    avg_overall = "%.1f" % _avg(all_overall) if all_overall else "—"
    avg_events  = "%.1f" % _avg(all_events)  if all_events  else "—"
    avg_nps     = "%.1f" % _avg(nps_vals)    if nps_vals    else "—"

    # --- Rating distribution (how many 1s, 2s, 3s, 4s, 5s across everything) ---
    dist = [0, 0, 0, 0, 0]  # index 0 = rating 5, index 4 = rating 1
    for v in all_overall:
        if 1 <= v <= 5:
            dist[5 - v] += 1
    rating_distribution = dist  # [count of 5s, 4s, 3s, 2s, 1s]

    # --- Semester rows for comparison table ---
    semester_rows = []
    for i, key in enumerate(SEMESTER_KEYS):
        semester_rows.append({
            'label': SEMESTER_LABELS[i],
            'overall': overall_by_sem[i] or 0,
            'events':  events_by_sem[i]  or 0,
            'comms':   comms_by_sem[i]   or 0,
            'team':    team_by_sem[i]    or 0,
        })

    # --- Event feedback aggregation ---
    event_feedback_list = []
    event_ids_seen = set()
    for r in event_responses:
        eid = r.get('event_id')
        if eid not in event_ids_seen:
            event_ids_seen.add(eid)
            matching = [x for x in event_responses if x.get('event_id') == eid]
            ef = matching[0].get('event_feedback', {})
            avg_fn = lambda cat: _avg([m['event_feedback'].get(cat, 0) for m in matching if m.get('event_feedback')])
            event_obj = EVENTS.get(eid, {})
            ev_nps_vals = []
            for m in matching:
                try:
                    ev_nps_vals.append(int(m['nps_score']))
                except Exception:
                    pass
            event_feedback_list.append({
                'event_title': event_obj.get('title', f'Event #{eid}'),
                'overall':     avg_fn('overall'),
                'org':         avg_fn('org'),
                'venue':       avg_fn('venue'),
                'engagement':  avg_fn('engagement'),
                'nps':         _avg(ev_nps_vals),
                'count':       len(matching),
            })

    # --- Qualitative quotes ---
    quotes = []
    for r in SURVEY_RESPONSES:
        for field, label in [
            ('keep_doing', 'Keep Doing'),
            ('improve', 'Improve'),
            ('open_feedback', 'Open Feedback'),
        ]:
            text = r.get(field, '').strip()
            if text and len(text) > 10:
                quotes.append({
                    'text': text,
                    'author': r['user_name'],
                    'label': label
                })

    stats = {
        'total_responses': len(sem_responses),
        'event_responses': len(event_responses),
        'avg_overall': avg_overall,
        'avg_events': avg_events,
        'avg_nps': avg_nps,
        'sem_labels': SEMESTER_LABELS,
        'overall_by_sem': overall_by_sem,
        'events_by_sem': events_by_sem,
        'comms_by_sem': comms_by_sem,
        'team_by_sem': team_by_sem,
        'budget_by_sem': budget_by_sem,
        'rating_distribution': rating_distribution,
        'semester_rows': semester_rows,
        'event_feedback_list': event_feedback_list,
        'quotes': quotes,
    }

    return render_template('stats.html', stats=stats, events=list(EVENTS.values()))


# ==========================================
# MEMBER PROFILE ("ME" PAGE)
# ==========================================

@app.route('/me', methods=['GET', 'POST'])
@login_required
def me_page():
    if request.method == 'POST':
        quote = request.form.get('quote', '').strip()
        picture_file = request.files.get('picture_file')
        picture_url = request.form.get('picture_url', '').strip()
        
        filename = ""
        if picture_file and allowed_file(picture_file.filename):
            filename = secure_filename(picture_file.filename)
            picture_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.picture = url_for('static', filename='uploads/' + filename)
        elif picture_url:
            current_user.picture = picture_url
            
        # Update STUCO_MEMBERS profile matching current_user.email
        for m in STUCO_MEMBERS:
            if m.get("email", "").lower() == current_user.email.lower():
                if quote: m["quote"] = quote
                if current_user.picture: m["picture"] = current_user.picture
                break
                
        # Update ACCOUNTS dict
        if current_user.email.lower() in ACCOUNTS:
            if current_user.picture:
                ACCOUNTS[current_user.email.lower()]["picture"] = current_user.picture
                
        save_data()
        flash("Profile & picture updated successfully!", "success")
        return redirect(url_for('me_page'))

    member_info = next((m for m in STUCO_MEMBERS if m.get("email", "").lower() == current_user.email.lower()), None)
    return render_template('me.html', member_info=member_info)


# ==========================================
# ADMIN: TRIGGER MICROSOFT FORMS SURVEY
# ==========================================

@app.route('/stats/trigger_survey', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def trigger_event_survey():
    survey_title = request.form.get('survey_title', 'Student Feedback Survey').strip()
    survey_link = request.form.get('survey_link', '').strip()
    qr_code_file = request.files.get('qr_code_file')
    qr_code_url = request.form.get('qr_code_url', '').strip()
    
    qr_src = ""
    if qr_code_file and allowed_file(qr_code_file.filename):
        qr_filename = secure_filename(qr_code_file.filename)
        qr_code_file.save(os.path.join(app.config['UPLOAD_FOLDER'], qr_filename))
        qr_src = url_for('static', filename='uploads/' + qr_filename)
    elif qr_code_url:
        qr_src = qr_code_url

    # Automatically post survey announcement to home page
    new_id = max([a['id'] for a in ANNOUNCEMENTS], default=0) + 1
    content_text = f"Please complete our Microsoft Forms survey for '{survey_title}'."
    if qr_src:
        content_text += " Scan the QR code or click the link below to participate!"

    ANNOUNCEMENTS.insert(0, {
        "id": new_id,
        "title": f"📋 Survey: {survey_title}",
        "date": "Today",
        "badge": "Student Voice",
        "badge_color": "priority",
        "content": content_text,
        "qr_code": qr_src,
        "link": survey_link or "/survey",
        "link_text": "Take Microsoft Forms Survey →"
    })
    
    save_data()
    flash(f"📬 Survey '{survey_title}' published to Home Page & sent to all members!", "success")
    return redirect(url_for('stats_page'))


# ==========================================
# ADMIN PORTAL ROUTES
# ==========================================

@app.route('/admin')
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def admin_page():
    return render_template('admin.html', accounts=ACCOUNTS, members=STUCO_MEMBERS)


@app.route('/admin/update_user', methods=['POST'])
@login_required
@require_role(['President', 'Vice President'])
def admin_update_user():
    email = request.form.get('email', '').strip().lower()
    name = request.form.get('name', '').strip()
    role = request.form.get('role', 'Student')
    can_edit_updates = request.form.get('can_edit_updates') == 'true'

    if not email:
        flash("Email is required.", "danger")
        return redirect(url_for('admin_page'))

    # Update or add new account
    ACCOUNTS[email] = {
        "name": name or email.split('@')[0],
        "role": role,
        "can_edit_updates": can_edit_updates
    }
    
    # If the user is currently logged in/active, update their session object
    for user_id, active_user in active_users.items():
        if active_user.email.lower() == email:
            active_user.role = role
            active_user.can_edit_updates = can_edit_updates
            active_user.name = ACCOUNTS[email]["name"]
            break

    save_data()
    flash(f"Account for {email} updated successfully!", "success")
    return redirect(url_for('admin_page'))


@app.route('/admin/delete_user', methods=['POST'])
@login_required
@require_role(['President', 'Vice President'])
def admin_delete_user():
    email = request.form.get('email', '').strip().lower()
    if email in ACCOUNTS:
        ACCOUNTS.pop(email)
        # Log out user if active
        for user_id, active_user in list(active_users.items()):
            if active_user.email.lower() == email:
                active_users.pop(user_id, None)
                break
        save_data()
        flash(f"Account {email} deleted successfully.", "success")
    return redirect(url_for('admin_page'))


@app.route('/admin/edit_leader', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def admin_edit_leader():
    index = _safe_int(request.form.get('index'), -1)
    name = request.form.get('name', '').strip()
    role = request.form.get('role', '').strip()
    grade = request.form.get('grade', '').strip()
    quote = request.form.get('quote', '').strip()
    email = request.form.get('email', '').strip()

    if 0 <= index < len(STUCO_MEMBERS):
        old_email = STUCO_MEMBERS[index].get("email", "").strip().lower()
        new_email = email.strip().lower()

        # Update profile
        STUCO_MEMBERS[index] = {
            "name": name,
            "role": role,
            "grade": grade,
            "quote": quote,
            "email": email
        }

        # Synchronize corresponding account in ACCOUNTS
        if old_email in ACCOUNTS:
            acct_data = ACCOUNTS.pop(old_email)
            acct_data["name"] = name
            
            # Map clean roles to account authorization levels
            acct_role = "Stuco Member"
            if "President" in role and "Vice" not in role:
                acct_role = "President"
            elif "Vice President" in role or "Vice-President" in role:
                acct_role = "Vice President"
            elif "Secretary" in role:
                acct_role = "Secretary"
            elif "Treasurer" in role:
                acct_role = "Treasurer"
            elif "Teacher" in role or "Advisor" in role:
                acct_role = "Teacher"
            acct_data["role"] = acct_role
            acct_data["can_edit_updates"] = acct_role in ["President", "Vice President", "Secretary", "Teacher"]
            
            ACCOUNTS[new_email] = acct_data

            # Update logged-in session values if matching
            for user_id, active_user in active_users.items():
                if active_user.email.lower() == old_email:
                    active_user.email = new_email
                    active_user.name = name
                    active_user.role = acct_role
                    active_user.can_edit_updates = acct_data["can_edit_updates"]
                    break
        else:
            # Create a new login account for this leader email if it wasn't registered
            acct_role = "Stuco Member"
            if "President" in role and "Vice" not in role:
                acct_role = "President"
            elif "Vice President" in role or "Vice-President" in role:
                acct_role = "Vice President"
            elif "Secretary" in role:
                acct_role = "Secretary"
            elif "Treasurer" in role:
                acct_role = "Treasurer"
            elif "Teacher" in role or "Advisor" in role:
                acct_role = "Teacher"
                
            ACCOUNTS[new_email] = {
                "name": name,
                "role": acct_role,
                "can_edit_updates": acct_role in ["President", "Vice President", "Secretary", "Teacher"]
            }

        save_data()
        flash(f"Leader profile for {name} updated successfully!", "success")
    return redirect(url_for('admin_page'))


# ==========================================
# STUCO UPDATES / ANNOUNCEMENTS ROUTES
# ==========================================

@app.route('/updates')
def updates_page():
    return render_template('updates.html', announcements=ANNOUNCEMENTS)


@app.route('/updates/add', methods=['POST'])
@login_required
def add_update():
    # Only allow Admin roles OR users explicitly granted can_edit_updates
    if current_user.role not in ['President', 'Vice President', 'Secretary', 'Teacher'] and not current_user.can_edit_updates:
        flash("🔒 Access Denied: You do not have permission to publish Stuco updates.", "danger")
        return redirect(url_for('updates_page'))

    from datetime import datetime
    title = request.form.get('title', '').strip()
    content = request.form.get('content', '').strip()
    badge = request.form.get('badge', 'General')
    badge_color = request.form.get('badge_color', 'community')
    link = request.form.get('link', '')
    link_text = request.form.get('link_text', 'Learn More →')

    if not title or not content:
        flash("Title and Content are required.", "danger")
        return redirect(url_for('updates_page'))

    new_id = max([a['id'] for a in ANNOUNCEMENTS], default=0) + 1
    ANNOUNCEMENTS.insert(0, {
        "id": new_id,
        "title": title,
        "date": datetime.now().strftime('%B %d, %Y'),
        "badge": badge,
        "badge_color": badge_color,
        "content": content,
        "link": link,
        "link_text": link_text
    })
    flash("Stuco update published successfully!", "success")
    return redirect(url_for('updates_page'))


@app.route('/updates/edit/<int:ann_id>', methods=['POST'])
@login_required
def edit_update(ann_id):
    if current_user.role not in ['President', 'Vice President', 'Secretary', 'Teacher'] and not current_user.can_edit_updates:
        flash("🔒 Access Denied: You do not have permission to edit Stuco updates.", "danger")
        return redirect(url_for('updates_page'))

    ann = next((a for a in ANNOUNCEMENTS if a['id'] == ann_id), None)
    if ann:
        ann["title"] = request.form.get('title', ann["title"])
        ann["content"] = request.form.get('content', ann["content"])
        ann["badge"] = request.form.get('badge', ann["badge"])
        ann["badge_color"] = request.form.get('badge_color', ann["badge_color"])
        ann["link"] = request.form.get('link', ann["link"])
        ann["link_text"] = request.form.get('link_text', ann["link_text"])
        flash("Stuco update updated successfully!", "success")
    return redirect(url_for('updates_page'))


@app.route('/updates/delete/<int:ann_id>', methods=['POST'])
@login_required
def delete_update(ann_id):
    if current_user.role not in ['President', 'Vice President', 'Secretary', 'Teacher'] and not current_user.can_edit_updates:
        flash("🔒 Access Denied: You do not have permission to delete Stuco updates.", "danger")
        return redirect(url_for('updates_page'))

    global ANNOUNCEMENTS
    ANNOUNCEMENTS = [a for a in ANNOUNCEMENTS if a['id'] != ann_id]
    flash("Stuco update deleted successfully.", "success")
    return redirect(url_for('updates_page'))


# ==========================================
# EVENTS & BOOKING URL ROUTES
# ==========================================

@app.route('/calendar/add', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def add_calendar_event():
    title = request.form.get('title', '').strip()
    date = request.form.get('date', '').strip()
    time = request.form.get('time', '').strip()
    location = request.form.get('location', '').strip()
    category = request.form.get('category', '').strip()
    scope = request.form.get('scope', 'Entire School').strip()
    requires_booking = request.form.get('requires_booking') in ['true', 'on'] or category == 'Paid Event'
    lead = request.form.get('lead', '').strip()
    budget = request.form.get('budget', '$0.00').strip()
    description = request.form.get('description', '').strip()

    if not title or not date:
        flash("Event Title and Date are required.", "danger")
        return redirect(url_for('public_calendar'))

    new_id = max(EVENTS.keys(), default=0) + 1
    
    # Format display date (e.g., Saturday, October 24, 2026)
    from datetime import datetime
    try:
        dt_obj = datetime.strptime(date, '%Y-%m-%d')
        display_date = dt_obj.strftime('%A, %B %d, %Y')
    except Exception:
        display_date = date

    EVENTS[new_id] = {
        "id": new_id,
        "title": title,
        "date": date,
        "display_date": display_date,
        "time": time or "TBD",
        "location": location or "Main Campus",
        "category": category or "Free School Event",
        "scope": scope,
        "requires_booking": requires_booking,
        "participants": [],
        "lead": lead or current_user.name,
        "budget_allocated": budget,
        "description": description,
        "ticket_link": "",
        "ticket_status": "Free Entry",
        "has_workspace": True,
        "schedule": [],
        "tasks": [],
        "photos": []
    }
    flash(f"Event '{title}' added to calendar!", "success")
    return redirect(url_for('public_calendar'))


@app.route('/calendar/edit/<int:event_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def edit_calendar_event(event_id):
    event = EVENTS.get(event_id)
    if event:
        category = request.form.get('category', event.get("category", "Free School Event"))
        requires_booking = request.form.get('requires_booking') in ['true', 'on'] or category == 'Paid Event'

        event["title"] = request.form.get('title', event["title"])
        event["time"] = request.form.get('time', event["time"])
        event["location"] = request.form.get('location', event["location"])
        event["category"] = category
        event["scope"] = request.form.get('scope', event.get("scope", "Entire School"))
        event["requires_booking"] = requires_booking
        event["lead"] = request.form.get('lead', event["lead"])
        event["budget_allocated"] = request.form.get('budget', event["budget_allocated"])
        event["description"] = request.form.get('description', event["description"])
        
        date = request.form.get('date', event["date"])
        if date != event["date"]:
            event["date"] = date
            from datetime import datetime
            try:
                dt_obj = datetime.strptime(date, '%Y-%m-%d')
                event["display_date"] = dt_obj.strftime('%A, %B %d, %Y')
            except Exception:
                event["display_date"] = date

        flash(f"Event '{event['title']}' updated successfully!", "success")
    return redirect(url_for('public_calendar'))


@app.route('/calendar/delete/<int:event_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def delete_calendar_event(event_id):
    if event_id in EVENTS:
        title = EVENTS[event_id]['title']
        EVENTS.pop(event_id)
        flash(f"Event '{title}' deleted from calendar.", "success")
    return redirect(url_for('public_calendar'))


@app.route('/calendar/edit_booking/<int:event_id>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President', 'Secretary', 'Teacher'])
def edit_event_booking(event_id):
    event = EVENTS.get(event_id)
    if event:
        booking_url = request.form.get('ticket_link', '').strip()
        ticket_status = request.form.get('ticket_status', 'Tickets Available').strip()
        event["ticket_link"] = booking_url
        event["ticket_status"] = ticket_status or "Free Entry"
        flash(f"Booking URL and status updated for '{event['title']}'!", "success")
    return redirect(url_for('public_calendar'))


# ==========================================
# VOLUNTEER OPPORTUNITIES DATA & ROUTES
# ==========================================

VOLUNTEER_OPPORTUNITIES = [
    {
        "id": 1,
        "event_id": 1,
        "title": "Homecoming Setup Crew",
        "date": "2026-10-24",
        "time": "12:00 PM - 4:00 PM",
        "hours_given": 4.0,
        "spots_needed": 10,
        "task_description": "Assemble tables, hang banners, test lighting systems, and arrange sound equipment in the Gym.",
        "signups": [
            {"email": "student@bjsmicschool.com", "name": "Sam V.", "approved": True},
            {"email": "volunteer_test@bjsmicschool.com", "name": "Alex Volunteer", "approved": False}
        ]
    },
    {
        "id": 2,
        "event_id": 2,
        "title": "Pep Rally Popsicle Distribution",
        "date": "2026-08-28",
        "time": "2:30 PM - 3:30 PM",
        "hours_given": 1.5,
        "spots_needed": 5,
        "task_description": "Pass out free popsicles to students entering the Central Courtyard during class competitions.",
        "signups": []
    }
]


@app.route('/volunteers')
@login_required
def volunteers_page():
    return render_template('volunteers.html', opportunities=VOLUNTEER_OPPORTUNITIES)


@app.route('/volunteers/signup/<int:op_id>', methods=['POST'])
@login_required
def signup_volunteer(op_id):
    op = next((o for o in VOLUNTEER_OPPORTUNITIES if o["id"] == op_id), None)
    if op:
        # Check if already signed up
        already_signed = any(s["email"].lower() == current_user.email.lower() for s in op["signups"])
        if already_signed:
            flash("You have already signed up for this opportunity!", "warning")
        else:
            op["signups"].append({
                "email": current_user.email.lower(),
                "name": current_user.name,
                "approved": False
            })
            flash("Successfully signed up! Wait for President or Vice President approval.", "success")
    return redirect(url_for('volunteers_page'))


@app.route('/volunteers/approve/<int:op_id>/<string:email>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President'])
def approve_volunteer(op_id, email):
    op = next((o for o in VOLUNTEER_OPPORTUNITIES if o["id"] == op_id), None)
    if op:
        for s in op["signups"]:
            if s["email"].lower() == email.lower():
                s["approved"] = True
                flash(f"Approved volunteer signup for {s['name']}!", "success")
                break
    return redirect(url_for('volunteers_page'))


@app.route('/volunteers/decline/<int:op_id>/<string:email>', methods=['POST'])
@login_required
@require_role(['President', 'Vice President'])
def decline_volunteer(op_id, email):
    op = next((o for o in VOLUNTEER_OPPORTUNITIES if o["id"] == op_id), None)
    if op:
        op["signups"] = [s for s in op["signups"] if s["email"].lower() != email.lower()]
        flash(f"Declined volunteer signup for {email}.", "success")
    return redirect(url_for('volunteers_page'))


# ==========================================
# SERVER INITIATION
# ==========================================

handler = app

if __name__ == '__main__':
    app.run(debug=True, port=5001)