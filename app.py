from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'shindolifecc'  # Secret key for session management

# Connect to the SQLite database (the same one we set up)
def get_db_connection():
    connection = sqlite3.connect('BeanBrew.db')
    connection.row_factory = sqlite3.Row  # So we can access columns by name
    return connection

# Home route
@app.route('/')
def home():
    return render_template('home.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:  # If the user is already logged in
        return redirect(url_for('home'))  # Redirect to home page

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password)  # Hash the password for security

        # Set default profile picture
        default_profile_picture = '/static/images/default_pfp.svg'

        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, profile_picture) VALUES (?, ?, ?, ?)",
                (username, hashed_password, email, default_profile_picture)
            )
            connection.commit()
            cursor.close()
            flash('Sign up successful! Please log in.', 'success')
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash('Username or email already exists. Please try again.', 'danger')

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:  # If the user is already logged in
        return redirect(url_for('home'))  # Redirect to home page

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user is None:
            flash('User not found. Please register.', 'danger')
        elif not check_password_hash(user['password'], password):
            flash('Incorrect password. Please try again.', 'danger')
        else:
            session['user_id'] = user['id']
            session['profile_picture'] = user['profile_picture'] if user['profile_picture'] else '/static/images/default_pfp.svg'
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()  # Clear the session data to log out the user
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Profile management route
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        # Handle profile picture upload
        if 'profile_picture' in request.files:
            profile_picture = request.files['profile_picture']
            if profile_picture.filename != '':
                filename = secure_filename(profile_picture.filename)
                profile_picture_path = os.path.join('static/uploads', filename)
                profile_picture.save(profile_picture_path)

                # Update profile picture in the database
                cursor.execute("UPDATE users SET profile_picture = ? WHERE id = ?", (profile_picture_path, session['user_id']))
                session['profile_picture'] = profile_picture_path  # Update session

        # Handle password change (if provided)
        if request.form['password']:
            password = generate_password_hash(request.form['password'])
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (password, session['user_id']))

        # Update username and email
        cursor.execute("UPDATE users SET username = ?, email = ? WHERE id = ?", (username, email, session['user_id']))
        connection.commit()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/book', methods=['GET', 'POST'])
def bookatable():
    if 'user_id' not in session:  # Ensure user is logged in
        flash('You must be logged in to book a table.', 'danger')
        return redirect(url_for('login'))

    connection = get_db_connection()
    cursor = connection.cursor()

    # Fetch already booked slots for the current date
    cursor.execute("SELECT date, time, SUM(people) as total_people FROM bookings GROUP BY date, time HAVING total_people >= 25")
    booked_data = cursor.fetchall()

    # Create a dictionary of booked slots
    booked_slots = {}
    for row in booked_data:
        date_str = row['date']
        if date_str not in booked_slots:
            booked_slots[date_str] = []
        booked_slots[date_str].append(row['time'])

    if request.method == 'POST':
        user_id = session['user_id']
        date = request.form['date']
        time = request.form['time']
        people = int(request.form['people'])

        # Check total bookings for the selected time slot
        cursor.execute("SELECT SUM(people) FROM bookings WHERE date = ? AND time = ?", (date, time))
        total_people = cursor.fetchone()[0] or 0

        if total_people + people > 25:
            flash(f'Sorry, we are fully booked for {time} on {date}.', 'danger')
        else:
            # Insert the booking
            cursor.execute(
                "INSERT INTO bookings (user_id, date, time, people) VALUES (?, ?, ?, ?)",
                (user_id, date, time, people)
            )
            connection.commit()
            flash('Booking successful! You have reserved a table.', 'success')

        cursor.close()
        return redirect(url_for('bookatable'))

    return render_template('booking.html', booked_slots=booked_slots)

if __name__ == '__main__':
    app.run(debug=True)
