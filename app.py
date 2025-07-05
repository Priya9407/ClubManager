from flask import Flask, redirect, url_for, session, request, flash, render_template, render_template_string, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import jwt
import datetime
import os
from dotenv import load_dotenv

load_dotenv()

clientid = os.getenv("GOOGLE_CLIENT_ID")
clientsecret = os.getenv("GOOGLE_CLIENT_SECRET")


app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['GOOGLE_CLIENT_ID'] = clientid
app.config['GOOGLE_CLIENT_SECRET'] = clientsecret
JWT_SECRET = app.secret_key

db = SQLAlchemy(app)
class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.String, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=True)
    role = db.Column(db.String(50), nullable=False)

    student = db.relationship('Student', back_populates='user', uselist=False)
    faculty = db.relationship('Faculty', back_populates='user', uselist=False)

class Faculty(db.Model):
    __tablename__ = 'faculty'

    faculty_id = db.Column(db.String, db.ForeignKey('user.id'), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    designation = db.Column(db.String(100), nullable=False)
    school = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(50), nullable=False)

    user = db.relationship('User', back_populates='faculty')
    coordinated_clubs = db.relationship('Club', back_populates='faculty_coordinator')

class Student(db.Model):
    __tablename__ = 'student'

    student_id = db.Column(db.String, db.ForeignKey('user.id'), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    school = db.Column(db.String(50), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)

    user = db.relationship('User', back_populates='student')
    memberships = db.relationship('Member', back_populates='student')
    clubs_presided = db.relationship('Club', back_populates='president')

class Club(db.Model):
    __tablename__ = 'club'

    club_id = db.Column(db.String, primary_key=True)
    club_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=False)

    president_id = db.Column(db.String, db.ForeignKey('student.student_id'), nullable=True)
    faculty_coordinator_id = db.Column(db.String, db.ForeignKey('faculty.faculty_id'), nullable=True)

    president = db.relationship('Student', back_populates='clubs_presided')
    faculty_coordinator = db.relationship('Faculty', back_populates='coordinated_clubs')
    members = db.relationship('Member', back_populates='club')

class Member(db.Model):
    __tablename__ = 'member'

    member_id = db.Column(db.String, primary_key=True)
    student_id = db.Column(db.String, db.ForeignKey('student.student_id'), nullable=False)
    club_id = db.Column(db.String, db.ForeignKey('club.club_id'), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='member')

    student = db.relationship('Student', back_populates='memberships')
    club = db.relationship('Club', back_populates='members')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_url='https://oauth2.googleapis.com/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params={'prompt': 'consent', 'access_type': 'offline'},
    api_base_url='https://www.googleapis.com/oauth2/v2/',
    userinfo_endpoint='https://www.googleapis.com/oauth2/v2/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
)

def create_jwt(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        id = request.form['id']
        email = request.form['email']
        password = request.form['password']
        role=request.form['role']

        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'User already exists'}), 409

        hashed_pw = generate_password_hash(password)
        user = User(id=id, email=email, password_hash=hashed_pw,role=role)
        db.session.add(user)
        db.session.commit()
        token = create_jwt(user)
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    return render_template("register.html")

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == 'POST':
        id = request.form['id']
        password = request.form['password']
        user = User.query.filter_by(email=id).first()
        if not user:
            user = User.query.filter_by(id=id).first()
        if not user or not user.password_hash:
            flash("User does not exist or password not set.Try login with google", "danger")
            return redirect(url_for('login'))
        if not check_password_hash(user.password_hash, password):
            flash("Check password or try login with google", "danger")
            return redirect(url_for('login'))
        token = create_jwt(user)
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    return render_template("index.html")

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    search_term = request.args.get('search', '').strip()

    if user.role == "admin":
        if search_term:
            clubs = Club.query \
            .outerjoin(Student, Club.president_id == Student.student_id) \
            .outerjoin(Faculty, Club.faculty_coordinator_id == Faculty.faculty_id) \
            .filter(
                (Club.club_id.ilike(f"%{search_term}%")) |
                (Club.club_name.ilike(f"%{search_term}%")) |
                (Club.description.ilike(f"%{search_term}%")) |
                (Club.category.ilike(f"%{search_term}%")) |
                (Student.name.ilike(f"%{search_term}%")) |
                (Faculty.name.ilike(f"%{search_term}%"))
            ).all()
        else:
            clubs = Club.query.all()

        return render_template("admin_dashboard.html", user=user, clubs=clubs, search_term=search_term)
    else:
        president=Member.query.filter_by(student_id=user.id).first()
        if president:
            club=Club.query.filter_by(club_id=president.club_id).first()
            if president.role=='president':
                members = Member.query.filter_by(club_id=club.club_id).join(Student).all()
                total=len(members)
                return render_template("president.html", user=user, club=club,members=members,total=total)
            elif president.role=='faculty_coordinator':
                members = Member.query.filter_by(club_id=club.club_id).join(Student).all()
                total=len(members)
                return render_template("faculty.html", user=user, club=club,members=members,total=total)
        
    return render_template("user_dashboard.html", user=user)


@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()
    user = User.query.filter_by(email=user_info['email']).first()
    print(user_info['email'])
    if not user:
        email = user_info['email']
        return redirect(url_for('register', email=email))

    jwt_token = create_jwt(user)
    session['user_id'] = user.id
    return redirect(url_for('dashboard'))

@app.route('/protected')
def protected():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if not token:
        return jsonify({'error': 'Token missing'}), 401
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return jsonify({'message': 'Protected access granted', 'user': decoded})
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 403
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 403

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.clear()
    return redirect(url_for('home'))


@app.route('/new_club', methods=['GET', 'POST'])
def new_club():
    if request.method == 'POST':

        club_id = request.form.get('club_id')
        club_name = request.form.get('club_name')
        description = request.form.get('description')
        category = request.form.get('category')
        president_id = request.form.get('president') or None
        faculty_id = request.form.get('faculty') or None

        if not all([club_id, club_name, description, category]):
            return "Missing required field", 400

        new_club = Club(
            club_id=club_id,
            club_name=club_name,
            description=description,
            category=category,
            president_id=president_id,
            faculty_coordinator_id=faculty_id
        )

        db.session.add(new_club)
        db.session.commit()

        if president_id:
            c_id=int(club_id.replace("CLUB", ""))
            president_member = Member(
                member_id=f"C{c_id:03d}P",
                student_id=president_id,
                club_id=club_id,
                role='president'
            )
            db.session.add(president_member)

        if faculty_id:
            cl_id=int(club_id.replace("CLUB", ""))
            faculty_member = Member(
                member_id=f"C{cl_id:03d}F",
                student_id=faculty_id,  
                club_id=club_id,
                role='faculty_coordinator'
            )
            db.session.add(faculty_member)

        db.session.commit()

        return redirect(url_for('dashboard'))

    last_club = Club.query.order_by(Club.club_id.desc()).first()
    if last_club:
        last_id = int(last_club.club_id.replace("CLUB", ""))
        next_id = last_id + 1
    else:
        next_id = 1
    next_club = f"CLUB{next_id:03d}"

    user_id = session.get("user_id")
    user = User.query.get(user_id)

    # Get a list of currently assigned faculty coordinator IDs (excluding None)
    assigned_faculty_ids = db.session.query(Club.faculty_coordinator_id).filter(
        Club.faculty_coordinator_id.isnot(None)
    )

    # Get all faculties that are NOT assigned as coordinators
    non_coordinator_faculties = Faculty.query.filter(
        ~Faculty.faculty_id.in_(assigned_faculty_ids)
    ).all()

    print(non_coordinator_faculties)
    non_president_students = Student.query.filter(
        ~Student.student_id.in_(db.session.query(Club.president_id))
    ).all()

    return render_template(
        "new_club.html",
        user=user,
        next_club=next_club,
        non_president_students=non_president_students,
        non_coordinator_faculties=non_coordinator_faculties
    )

@app.route('/view_club/<club_id>', methods=['GET', 'POST'])
def view_club(club_id):
    club = Club.query.get_or_404(club_id)
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    members = Member.query.filter_by(club_id=club_id).join(Student).all()
    total=len(members)
    return render_template("view_club.html", user=user, club=club,members=members,total=total)

@app.route('/view_clubs', methods=['GET', 'POST'])
def view_clubs():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    search_term = request.args.get('search', '').strip()

    if user.role == "admin":
        if search_term:
            clubs = Club.query \
            .outerjoin(Student, Club.president_id == Student.student_id) \
            .outerjoin(Faculty, Club.faculty_coordinator_id == Faculty.faculty_id) \
            .filter(
                (Club.club_id.ilike(f"%{search_term}%")) |
                (Club.club_name.ilike(f"%{search_term}%")) |
                (Club.description.ilike(f"%{search_term}%")) |
                (Club.category.ilike(f"%{search_term}%")) |
                (Student.name.ilike(f"%{search_term}%")) |
                (Faculty.name.ilike(f"%{search_term}%"))
            ).all()
        else:
            clubs = Club.query.all()

    return render_template("view_clubs.html", user=user, clubs=clubs)

@app.route('/edit_club/<club_id>', methods=['GET', 'POST'])
def edit_club(club_id):
    club = Club.query.get_or_404(club_id)

    if request.method == 'POST':
        club.club_name = request.form.get("club_name")
        club.description = request.form.get("description")
        club.category = request.form.get("category")
        president_val = request.form.get("president")
        faculty_val = request.form.get("faculty")

        # Store old IDs to check if they changed
        old_president_id = club.president_id
        old_faculty_id = club.faculty_coordinator_id

        # Update club object
        club.president_id = president_val if president_val else None
        club.faculty_coordinator_id = faculty_val if faculty_val else None
        db.session.commit()

        # Club ID formatting helper
        club_num = club.club_id.replace("CLUB", "")
        pres_member_id = f"C{club_num}P"
        fac_member_id = f"C{club_num}F"

        # --- Handle President ---
        if old_president_id and old_president_id != president_val:
            Member.query.filter_by(member_id=pres_member_id, club_id=club_id).delete()

        if president_val and not Member.query.filter_by(member_id=pres_member_id).first():
            new_pres = Member(
                member_id=pres_member_id,
                student_id=president_val,
                club_id=club_id,
                role="president"
            )
            db.session.add(new_pres)

        # --- Handle Faculty ---
        if old_faculty_id and old_faculty_id != faculty_val:
            Member.query.filter_by(member_id=fac_member_id, club_id=club_id).delete()

        if faculty_val and not Member.query.filter_by(member_id=fac_member_id).first():
            new_fac = Member(
                member_id=fac_member_id,
                student_id=faculty_val,  # reuse student_id field for faculty
                club_id=club_id,
                role="faculty_coordinator"
            )
            db.session.add(new_fac)

        db.session.commit()
        flash("Club and member data updated successfully", "success")
        return redirect(url_for("dashboard"))

    # GET request — form population logic (unchanged)
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    president_ids = db.session.query(Club.president_id).filter(
        Club.club_id != club.club_id,
        Club.president_id.isnot(None)
    ).all()
    president_ids = [pid[0] for pid in president_ids]

    non_president_students = Student.query.filter(
        ~Student.student_id.in_(president_ids)
    ).all()

    coordinator_ids = db.session.query(Club.faculty_coordinator_id).filter(
        Club.club_id != club.club_id,
        Club.faculty_coordinator_id.isnot(None)
    ).all()
    coordinator_ids = [fid[0] for fid in coordinator_ids]

    non_coordinator_faculties = Faculty.query.filter(
        ~Faculty.faculty_id.in_(coordinator_ids)
    ).all()

    return render_template("edit_club.html", user=user, club=club,
                           non_president_students=non_president_students,
                           non_coordinator_faculties=non_coordinator_faculties)


@app.route('/search_club', methods=['POST'])
def search_club():
    search_term = request.form.get('search', '').strip()
    return redirect(url_for('dashboard', search=search_term))

@app.route('/view_search_club', methods=['POST'])
def view_search_club():
    search_term = request.form.get('search', '').strip()
    return redirect(url_for('view_clubs', search=search_term))

@app.route('/club/<club_id>/delete', methods=['POST','GET'])
def delete_club(club_id):
    club = Club.query.get(club_id)

    if not club:
        flash('Club not found.', 'danger')
        return redirect(url_for('view_clubs'))

    Member.query.filter_by(club_id=club_id).delete()

    db.session.delete(club)
    db.session.commit()

    flash(f'Club "{club.club_name}" deleted successfully.', 'success')
    return redirect(url_for('view_clubs'))

@app.route('/members/manage', methods=['GET', 'POST'])
def manage_members():
    clubs = Club.query.all()
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    president=Member.query.filter_by(student_id=user_id).first()
    print(president)
    if user.role == 'admin':
        first_club = Club.query.order_by(Club.club_id).first()
    elif president.role=='president':
        first_club = Club.query.filter_by(president_id=user_id).first()
        return redirect(url_for('manage_members_for_president', club_id=first_club.club_id))
    else:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    last_club_id = session.get("last_club_id")
    if last_club_id and any(c.club_id == last_club_id for c in clubs):
        return redirect(url_for('manage_members_for_club', club_id=last_club_id))

    if clubs:
        return redirect(url_for('manage_members_for_club', club_id=clubs[0].club_id))
    
    flash("No clubs found.", "warning")
    return redirect(url_for('dashboard'))

@app.route('/club/<club_id>/members', methods=['GET'])
def manage_members_for_club(club_id):
    session['last_club_id'] = club_id
    club = Club.query.get(club_id)
    clubs = Club.query.all()
    if not club:
        flash('Club not found.', 'danger')
        return redirect(url_for('manage_members'))
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    members = Member.query.filter(
        Member.club_id == club_id,
        Member.role != 'president'  # exclude president
    ).join(Student).all()
    current_member_ids = [m.student_id for m in Member.query.filter_by(club_id=club_id)]
    club_president_id = club.president_id

    non_members = Student.query.filter(
        ~Student.student_id.in_(current_member_ids + [club_president_id])
    ).all()


    return render_template('manage_members.html', clubs=clubs,club=club, members=members, non_members=non_members,user=user)

@app.route('/club/<club_id>/president', methods=['GET'])
def manage_members_for_president(club_id):
    club = Club.query.get(club_id)
    print(club_id)
    if not club:
        flash('Club not found.', 'danger')
        return redirect(url_for('manage_members'))
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    members = Member.query.filter(
        Member.club_id == club_id,
        Member.role != 'president'  
    ).join(Student).all()
    current_member_ids = [m.student_id for m in Member.query.filter_by(club_id=club_id)]
    club_president_id = club.president_id

    non_members = Student.query.filter(
        ~Student.student_id.in_(current_member_ids + [club_president_id])
    ).all()


    return render_template('manage_members_for_president.html', club=club, members=members, non_members=non_members,user=user)


@app.route('/club/<club_id>/members/add', methods=['POST'])
def add_member(club_id):
    student_id = request.form.get('student_id')
   
    exists = Member.query.filter_by(club_id=club_id, student_id=student_id).first()
    if exists:
        flash('Student is already a member.', 'warning')
    else:
        member_id = generate_next_member_id(club_id)

        new_member = Member(member_id=member_id, club_id=club_id, student_id=student_id)
        db.session.add(new_member)
        db.session.commit()
        flash('Member added successfully.', 'success')
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    president=Member.query.filter_by(student_id=user_id).first()
    if president.role=='president':
        return redirect(url_for('manage_members_for_president', club_id=club_id))
    return redirect(url_for('manage_members_for_club', club_id=club_id))


@app.route('/club/<club_id>/members/remove/<student_id>', methods=['POST'])
def remove_member(club_id, student_id):
    member = Member.query.filter_by(club_id=club_id, student_id=student_id).first()
    if member:
        db.session.delete(member)
        db.session.commit()
        flash('Member removed.', 'success')
    else:
        flash('Member not found.', 'danger')
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    president=Member.query.filter_by(student_id=user_id).first()
    if president.role=='president':
        return redirect(url_for('manage_members_for_president', club_id=club_id))
    return redirect(url_for('manage_members_for_club', club_id=club_id))

@app.route('/members/select', methods=['GET', 'POST'])
def select_club_for_members():
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if user.role == 'admin':
        clubs = Club.query.all()
    elif session.get('role') == 'president':
        user_id = session.get('user_id')
        clubs = Club.query.filter_by(president_id=user_id).all()
    else:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        selected_club_id = request.form.get('club_id')
        return redirect(url_for('manage_members', club_id=selected_club_id,user=user))

    return render_template('select_club.html', clubs=clubs,user=user)

@app.route('/assign_roles', methods=['GET', 'POST'])
def assign_roles():
    clubs = Club.query.all()
    user_id = session.get("user_id")
    user = User.query.get(user_id)

    if request.method == 'POST':
        selected_club_id = request.form.get('club_id')
        return redirect(url_for('assign_roles_for_club', club_id=selected_club_id))

    last_club_id = session.get("last_club_id")
    if last_club_id and any(c.club_id == last_club_id for c in clubs):
        return redirect(url_for('assign_roles_for_club', club_id=last_club_id))

    if clubs:
        return redirect(url_for('assign_roles_for_club', club_id=clubs[0].club_id))

    flash("No clubs found.", "warning")
    return redirect(url_for('dashboard'))


@app.route('/assign_roles/<club_id>', methods=['GET', 'POST'])
def assign_roles_for_club(club_id):
    session['last_club_id'] = club_id
    club = Club.query.get_or_404(club_id)
    clubs = Club.query.all()
    user_id = session.get("user_id")
    user = User.query.get(user_id)
    if request.method == 'POST':
        president_id = request.form.get('president_id') or None
        faculty_id = request.form.get('faculty_id') or None

        # Ensure no duplicate assignment
        other_clubs = Club.query.filter(Club.club_id != club_id)

        if president_id and other_clubs.filter_by(president_id=president_id).first():
            flash('This student is already president of another club.', 'danger')
        elif faculty_id and other_clubs.filter_by(faculty_coordinator_id=faculty_id).first():
            flash('This faculty is already coordinator of another club.', 'danger')
        else:
            old_president_id = club.president_id
            old_faculty_id = club.faculty_coordinator_id
            club.president_id = president_id
            club.faculty_coordinator_id = faculty_id
            db.session.commit()
            if old_president_id:
                old_pres_member_id = f"C{club_id.replace('CLUB','')}P"
                Member.query.filter_by(club_id=club_id, member_id=old_pres_member_id).delete()

            # Add new president if not already a member
            if president_id:
                new_pres_member_id = f"C{club_id.replace('CLUB','')}P"
                if not Member.query.filter_by(member_id=new_pres_member_id).first():
                    new_pres = Member(
                        member_id=new_pres_member_id,
                        student_id=president_id,
                        club_id=club_id,
                        role="president"
                    )
                    db.session.add(new_pres)

            # Remove old faculty coordinator entry if exists
            if old_faculty_id:
                old_fac_member_id = f"C{club_id.replace('CLUB','')}F"
                Member.query.filter_by(club_id=club_id, member_id=old_fac_member_id).delete()

            # Add new faculty as member (stored in student_id field for now)
            if faculty_id:
                new_fac_member_id = f"C{club_id.replace('CLUB','')}F"
                if not Member.query.filter_by(member_id=new_fac_member_id).first():
                    new_fac = Member(
                        member_id=new_fac_member_id,
                        student_id=faculty_id,  # Keep using student_id field for both
                        club_id=club_id,
                        role="faculty_coordinator"
                    )
                    db.session.add(new_fac)

            db.session.commit()
            flash('Roles updated successfully.', 'success')
            return redirect(url_for('assign_roles'))

    # Get unassigned students and faculty
    all_students = Student.query.all()
    all_faculties = Faculty.query.all()

    assigned_presidents = db.session.query(Club.president_id).filter(Club.club_id != club_id).all()
    assigned_presidents = {sid[0] for sid in assigned_presidents if sid[0]}
    available_students = [s for s in all_students if s.student_id not in assigned_presidents]

    assigned_faculty = db.session.query(Club.faculty_coordinator_id).filter(Club.club_id != club_id).all()
    assigned_faculty = {fid[0] for fid in assigned_faculty if fid[0]}
    available_faculty = [f for f in all_faculties if f.faculty_id not in assigned_faculty]

    return render_template(
        'assign_roles.html',
        club=club,clubs=clubs,
        available_students=available_students,
        available_faculty=available_faculty,user=user
    )

def generate_next_member_id(club_id):
    # Convert club_id like CLUB001 → 001
    club_num = club_id.replace("CLUB", "")
    prefix = f"C{club_num}M"

    # Get existing member_ids for this club
    existing_ids = Member.query.filter_by(club_id=club_id).with_entities(Member.member_id).all()

    # Extract numeric part (after 'M') and sort
    existing_numbers = sorted(
        int(mid[0].replace(prefix, ""))
        for mid in existing_ids
        if mid[0].startswith(prefix) and mid[0].replace(prefix, "").isdigit()
    )

    # Find smallest missing positive integer
    next_num = 1
    for num in existing_numbers:
        if num == next_num:
            next_num += 1
        else:
            break

    return f"{prefix}{next_num}"

if __name__ == '__main__':
    app.run(debug=True)
