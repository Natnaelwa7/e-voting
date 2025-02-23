from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///evoting.db'
app.config['SECRET_KEY'] = secrets.token_hex(16)  # Secure secret key
db = SQLAlchemy(app)

# Database Models
class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    votes = db.Column(db.Integer, default=0)

class ElectionOfficer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Initialize Sample Data
def init_sample_data():
    if not Candidate.query.first():
        db.session.add(Candidate(name="Candidate A"))
        db.session.add(Candidate(name="Candidate B"))
        db.session.commit()

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_voter = Voter(name=name, email=email, password=hashed_password)
        db.session.add(new_voter)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Voter.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if user.has_voted:
                flash('You have already voted!', 'warning')
            else:
                return redirect(url_for('vote', voter_id=user.id))
        else:
            flash('Invalid credentials!', 'danger')
    return render_template('login.html')

@app.route('/vote/<int:voter_id>', methods=['GET', 'POST'])
def vote(voter_id):
    voter = Voter.query.get_or_404(voter_id)
    candidates = Candidate.query.all()

    if request.method == 'POST':
        selected_candidate_id = request.form.get('candidate')
        if not selected_candidate_id:
            flash('Please select a candidate!', 'warning')
            return redirect(url_for('vote', voter_id=voter_id))

        candidate = Candidate.query.get(selected_candidate_id)
        if not candidate:
            flash('Invalid candidate selected!', 'danger')
            return redirect(url_for('vote', voter_id=voter_id))

        candidate.votes += 1
        voter.has_voted = True
        db.session.commit()
        flash('Your vote has been recorded successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('vote.html', voter=voter, candidates=candidates)

@app.route('/results')
def results():
    candidates = Candidate.query.all()
    return render_template('results.html', candidates=candidates)

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        # Input validation
        if not name:
            flash('Name cannot be empty!', 'danger')
            return redirect(url_for('admin_register'))
        if not email or '@' not in email:
            flash('Please enter a valid email address!', 'danger')
            return redirect(url_for('admin_register'))
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return redirect(url_for('admin_register'))

        # Check if email already exists
        existing_officer = ElectionOfficer.query.filter_by(email=email).first()
        if existing_officer:
            flash('Email already registered!', 'warning')
            return redirect(url_for('admin_register'))

        # Hash the password and create a new officer
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_officer = ElectionOfficer(name=name, email=email, password=hashed_password)
        db.session.add(new_officer)
        db.session.commit()
        flash('Election Officer registered successfully!', 'success')
        return redirect(url_for('admin_login'))

    return render_template('admin_register.html')

@app.route('/admin/add_candidate', methods=['GET', 'POST'])
def add_candidate():
    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash('Candidate name cannot be empty!', 'danger')
            return redirect(url_for('add_candidate'))
        new_candidate = Candidate(name=name)
        db.session.add(new_candidate)
        db.session.commit()
        flash(f'Candidate "{name}" added successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('add_candidate.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password'].strip()

        # Input validation
        if not email or '@' not in email:
            flash('Please enter a valid email address!', 'danger')
            return redirect(url_for('admin_login'))
        if not password:
            flash('Password cannot be empty!', 'danger')
            return redirect(url_for('admin_login'))

        # Authenticate the officer
        officer = ElectionOfficer.query.filter_by(email=email).first()
        if officer and check_password_hash(officer.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials!', 'danger')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    voters = Voter.query.all()
    candidates = Candidate.query.all()
    officers = ElectionOfficer.query.all()

    return render_template('admin_dashboard.html', voters=voters, candidates=candidates, officers=officers)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_sample_data()
    app.run(debug=True)