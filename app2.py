import streamlit as st
import base64
import pyotp
import smtplib
from email.message import EmailMessage
import time
import re
import string
import random

def add_bg_from_local(image_file):
    with open(image_file, "rb") as img_file:
        encoded_string = base64.b64encode(img_file.read()).decode()

    st.markdown(
        f"""
        <style>
        .stApp {{
            background: url("data:image/png;base64,{encoded_string}");
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed;
        }}

        /* Remove Streamlit's default white space */
        header {{
            visibility: hidden;
        }}

        /* Title Styling - Now stays in one line */
        .title-container {{
            text-align: center;
            font-size: 42px;
            font-weight: bold;
            color: white;
            text-shadow: 2px 2px 8px black;
            margin-top: 20px;
            white-space: nowrap;
            overflow: hidden;
            padding: 0 20px;
        }}

        /* Top-right buttons */
        .top-right {{
            position: absolute;
            top: 10px;
            right: 20px;
            display: flex;
            gap: 10px;
        }}

        .top-right button {{
            padding: 8px 12px;
            font-size: 16px;
            background-color: white;
            border-radius: 5px;
            border: none;
            cursor: pointer;
        }}
        
        /* Sidebar styling */
        .sidebar .sidebar-content {{
            background-color: rgba(255, 255, 255, 0.9);
        }}
        
        /* Content box styling */
        .content-box {{
            background-color: rgba(255, 255, 255, 0.9);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }}
        
        /* Feature list styling */
        .feature-list {{
            margin-top: 15px;
            padding-left: 20px;
        }}
        
        .feature-list li {{
            margin-bottom: 8px;
            font-size: 16px;
        }}
        
        /* Make forms more readable */
        .stForm {{
            background-color: rgba(255, 255, 255, 0.8);
            padding: 20px;
            border-radius: 10px;
        }}
        
        /* Horizontal button styling */
        .horizontal-buttons {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }}
        
        .horizontal-buttons button {{
            flex: 1;
            padding: 10px;
            font-size: 16px;
        }}
        
        .horizontal-buttons button.active {{
            background-color: #4CAF50;
            color: white;
        }}

        /* Section styling */
        .section-header {{
            margin-top: 20px;
            margin-bottom: 10px;
            color: #2E7D32;
            border-bottom: 1px solid #E0E0E0;
            padding-bottom: 5px;
        }}

        /* Help text */
        .help-text {{
            font-size: 12px;
            color: #666;
            margin-top: -15px;
            margin-bottom: 15px;
        }}

        /* OTP container styling */
        .otp-container {{
            margin-top: 20px;
            padding: 15px;
            background-color: #f5f5f5;
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
        }}

        /* Success message styling */
        .success-container {{
            background-color: rgba(76, 175, 80, 0.1);
            border-left: 5px solid #4CAF50;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            text-align: center;
        }}
        
        .success-icon {{
            font-size: 48px;
            color: #4CAF50;
            margin-bottom: 10px;
        }}
        
        .success-title {{
            font-size: 24px;
            font-weight: bold;
            color: #2E7D32;
            margin-bottom: 10px;
        }}
        
        .success-message {{
            font-size: 16px;
            margin-bottom: 20px;
        }}
        
        /* Error message styling */
        .error-container {{
            background-color: rgba(255, 0, 0, 0.1);
            border-left: 5px solid #FF0000;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        
        /* Password strength meter */
        .password-strength {{
            height: 5px;
            margin-top: 5px;
            margin-bottom: 15px;
            background-color: #e0e0e0;
            border-radius: 3px;
            overflow: hidden;
        }}
        
        .password-strength-bar {{
            height: 100%;
            width: 0%;
            transition: width 0.3s;
        }}
        
        /* Responsive adjustments */
        @media (max-width: 768px) {{
            .title-container {{
                font-size: 32px;
            }}
            
            .horizontal-buttons {{
                flex-direction: column;
            }}
        }}
        </style>
        """,
        unsafe_allow_html=True
    )

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_phone(phone):
    """Validate phone number (10 digits)"""
    return phone.isdigit() and len(phone) == 10

def validate_password(password):
    """Check password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search("[a-z]", password):
        return False, "Password must contain lowercase letters"
    if not re.search("[A-Z]", password):
        return False, "Password must contain uppercase letters"
    if not re.search("[0-9]", password):
        return False, "Password must contain numbers"
    if not re.search("[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain special characters"
    return True, "Strong password"

def mask_email(email):
    """
    Masks the email address for privacy
    Shows only first character and domain
    Example: test@example.com -> t****@example.com
    """
    if not email or '@' not in email:
        return email
    
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    
    # Keep just the first character of the username
    if len(username) > 1:
        masked_username = username[0] + '*' * (len(username) - 1)
    else:
        masked_username = username
        
    return f"{masked_username}@{domain}"

def send_email(receiver_email, subject, content_type="verification", code=None):
    """Send emails with improved deliverability"""
    # Generate OTP or reset code if not provided
    if code is None:
        if content_type == "verification":
            # Generate OTP for verification
            secret_key = pyotp.random_base32()
            totp = pyotp.TOTP(secret_key, interval=180)  # 3-minute validity
            code = totp.now()
            
            # Store OTP in session state for verification
            st.session_state.otp_secret = secret_key
            st.session_state.otp_time = time.time()
            st.session_state.otp_attempts = 0  # Track OTP attempts
        else:
            # Generate random reset code for password reset
            characters = string.ascii_letters + string.digits
            code = ''.join(random.choice(characters) for _ in range(6))
            
            # Store reset code in session state
            st.session_state.reset_code = code
            st.session_state.reset_code_time = time.time()
            st.session_state.reset_attempts = 0
    
    # Email configuration
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 465
    SENDER_NAME = "AgricultureChatbot"
    SENDER_EMAIL = "rishiande99999@gmail.com"
    SENDER_PASSWORD = "vnhhrieggmpngufz"  # Note: In a production app, use environment variables for sensitive data
    
    # Prepare Email
    msg = EmailMessage()
    
    # Set important headers to avoid spam
    msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg["X-Priority"] = "1"  # High priority
    msg["X-Mailer"] = "AgricultureChatbot"
    msg["Importance"] = "High"
    
    # Choose template based on content type
    if content_type == "verification":
        # Plain text version - verification
        plain_text = f"""Agriculture Planning System Verification

Your one-time verification code is: {code}

This code will expire in 3 minutes.

If you didn't request this code, please ignore this email.

Thank you,
Agriculture Planning System Team
"""
        # HTML version - verification
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Your Verification Code</title>
        </head>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 20px;">
                    <h1 style="color: #2E7D32; margin-bottom: 5px;">🌾 Smart Agriculture</h1>
                    <p style="color: #666; font-size: 16px;">Account Verification</p>
                </div>
                
                <div style="background-color: #E8F5E9; padding: 25px; border-radius: 8px; text-align: center; margin: 25px 0;">
                    <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">Your verification code is:</p>
                    <div style="font-size: 32px; color: #4CAF50; font-weight: bold; letter-spacing: 5px; margin: 15px 0;">{code}</div>
                    <p style="margin: 0; color: #666; font-size: 14px;">(Expires in 3 minutes)</p>
                </div>
                
                <div style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px;">
                    <p style="color: #999; font-size: 12px; line-height: 1.5;">
                        If you didn't request this code, please ignore this email or contact support if you have questions.
                        <br><br>
                        This email was sent to {receiver_email} as part of your account registration with Agriculture Planning System.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    else:
        # Plain text version - password reset
        plain_text = f"""Agriculture Planning System Password Reset

You have requested to reset your password.

Your password reset code is: {code}

This code will expire in 3 minutes.

If you didn't request this code, please ignore this email.

Thank you,
Agriculture Planning System Team
"""
        # HTML version - password reset
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Password Reset Code</title>
        </head>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="text-align: center; margin-bottom: 20px;">
                    <h1 style="color: #2E7D32; margin-bottom: 5px;">🌾 Smart Agriculture</h1>
                    <p style="color: #666; font-size: 16px;">Password Reset Request</p>
                </div>
                
                <div style="background-color: #E8F5E9; padding: 25px; border-radius: 8px; text-align: center; margin: 25px 0;">
                    <p style="margin: 0 0 10px 0; color: #666; font-size: 14px;">Your password reset code is:</p>
                    <div style="font-size: 32px; color: #4CAF50; font-weight: bold; letter-spacing: 5px; margin: 15px 0;">{code}</div>
                    <p style="margin: 0; color: #666; font-size: 14px;">(Expires in 3 minutes)</p>
                </div>
                
                <div style="border-top: 1px solid #eee; padding-top: 20px; margin-top: 20px;">
                    <p style="color: #999; font-size: 12px; line-height: 1.5;">
                        If you didn't request this code, please ignore this email. Your account remains secure.
                        <br><br>
                        This email was sent to {receiver_email} in response to your password reset request.
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    
    msg.set_content(plain_text)
    msg.add_alternative(html_content, subtype='html')
    
    # Send Email
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        return True, code
    except Exception as e:
        st.error(f"Error sending email: {str(e)}")
        return False, None

def send_otp_email(receiver_email):
    """Send OTP email - wrapper for backward compatibility"""
    success, _ = send_email(
        receiver_email, 
        f"Your Agriculture Verification Code", 
        content_type="verification"
    )
    return success

def send_reset_email(receiver_email):
    """Send Password Reset email"""
    success, code = send_email(
        receiver_email, 
        f"Your Agriculture Password Reset Code", 
        content_type="reset"
    )
    return success, code

def verify_otp(entered_otp):
    """Verify OTP with attempt tracking"""
    if 'otp_secret' not in st.session_state or 'otp_time' not in st.session_state:
        return False
    
    # Track attempts
    if 'otp_attempts' not in st.session_state:
        st.session_state.otp_attempts = 0
    
    st.session_state.otp_attempts += 1
    
    # Check if too many attempts
    if st.session_state.otp_attempts > 3:
        st.error("Too many attempts. Please request a new OTP.")
        return False
    
    # Check if OTP is expired (3 minutes)
    current_time = time.time()
    if current_time - st.session_state.otp_time > 180:
        st.error("OTP has expired. Please request a new one.")
        return False
    
    # Verify OTP
    totp = pyotp.TOTP(st.session_state.otp_secret, interval=180)
    return totp.verify(entered_otp)

def verify_reset_code(entered_code):
    """Verify password reset code"""
    if 'reset_code' not in st.session_state or 'reset_code_time' not in st.session_state:
        return False
    
    # Track attempts
    if 'reset_attempts' not in st.session_state:
        st.session_state.reset_attempts = 0
    
    st.session_state.reset_attempts += 1
    
    # Check if too many attempts
    if st.session_state.reset_attempts > 3:
        st.error("Too many attempts. Please request a new reset code.")
        return False
    
    # Check if code is expired (3 minutes)
    current_time = time.time()
    if current_time - st.session_state.reset_code_time > 180:
        st.error("Reset code has expired. Please request a new one.")
        return False
    
    # Simple string comparison for reset code
    return st.session_state.reset_code == entered_code

def show_password_strength(password):
    """Show password strength meter"""
    strength = 0
    feedback = ""
    
    # Length check
    if len(password) >= 8:
        strength += 1
    
    # Complexity checks
    checks = [
        (r'[a-z]', "lowercase"),
        (r'[A-Z]', "uppercase"),
        (r'[0-9]', "number"),
        (r'[^A-Za-z0-9]', "special char")
    ]
    
    for pattern, name in checks:
        if re.search(pattern, password):
            strength += 1
            feedback += f"✓ {name} "
        else:
            feedback += f"✗ {name} "
    
    # Determine color and width
    # Fix: Ensure strength is within bounds of colors list
    colors = ["#FF0000", "#FF4500", "#FFA500", "#9ACD32", "#008000"]
    color_index = min(strength, len(colors) - 1)  # Ensure index is within bounds
    width = (strength / (len(checks) + 1) * 100)
    
    st.markdown(
        f"""
        <div class="password-strength">
            <div class="password-strength-bar" style="width:{width}%; background-color:{colors[color_index]};"></div>
        </div>
        <div style="font-size:12px; color:#666; margin-top:-10px;">{feedback}</div>
        """,
        unsafe_allow_html=True
    )

# Initialize session states
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = 'login'
if 'signup_stage' not in st.session_state:
    st.session_state.signup_stage = 'info'
if 'reset_stage' not in st.session_state:
    st.session_state.reset_stage = 'request'
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}
if 'verification_success' not in st.session_state:
    st.session_state.verification_success = False
if 'show_proceed_button' not in st.session_state:
    st.session_state.show_proceed_button = False
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0
if 'reset_email' not in st.session_state:
    st.session_state.reset_email = ""

# Set background
try:
    add_bg_from_local("C:/Users/rishi/Desktop/Agriculture/agriculture (2).jpg")
except FileNotFoundError:
    st.warning("Background image not found. Using default background.")

# Create sidebar navigation
with st.sidebar:
    st.title("🌾 Navigation")
    selected_page = st.radio("Go to", ["Project Landing Page", "Login/Signup"])

# Display title
st.markdown('<div class="title-container">Smart Agriculture Planning System</div>', unsafe_allow_html=True)

# Display content based on sidebar selection
if selected_page == "Project Landing Page":
    st.markdown(
        """
        <div class="content-box">
            <h2>About the Project</h2>
            <p>The Smart Agriculture Assistant is an AI-powered web application designed to assist farmers and agricultural professionals in optimizing crop management, irrigation scheduling, yield prediction, and weather monitoring. The platform integrates Google Gemini AI for intelligent recommendations and the OpenWeather API for real-time weather updates.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
else:
    # Horizontal buttons for Login/Signup
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login", key="login_btn", use_container_width=True, 
                   type="primary" if st.session_state.active_tab == 'login' else "secondary"):
            st.session_state.active_tab = 'login'
            st.session_state.signup_stage = 'info'
            st.session_state.reset_stage = 'request'
            st.session_state.verification_success = False
            st.rerun()
    with col2:
        if st.button("Sign Up", key="signup_btn", use_container_width=True,
                   type="primary" if st.session_state.active_tab == 'signup' else "secondary"):
            st.session_state.active_tab = 'signup'
            st.session_state.signup_stage = 'info'
            st.session_state.verification_success = False
            st.rerun()
    
    # Display the appropriate form based on the active tab
    if st.session_state.active_tab == 'login':
        # Check if coming from successful verification
        if st.session_state.verification_success:
            st.markdown(
                """
                <div class="success-container">
                    <div class="success-icon">✅</div>
                    <div class="success-title">Account Successfully Created!</div>
                    <div class="success-message">Your account has been created and verified. Please login below to continue to the Agriculture Chatbot.</div>
                </div>
                """,
                unsafe_allow_html=True
            )
            # Reset the success flag
            st.session_state.verification_success = False
        
        # Login Form
        with st.form("Login Form"):
            st.subheader("Login to Your Account")
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            remember_me = st.checkbox("Remember me")
            
            col1, col2 = st.columns([1, 2])
            with col1:
                login_submit = st.form_submit_button("Login", use_container_width=True)
            with col2:
                forgot_password = st.form_submit_button("Forgot Password?", use_container_width=True)
            
            if login_submit:
                if not username or not password:
                    st.error("Please enter both username and password")
                else:
                    # Simulate authentication
                    if len(password) >= 8:  # Simple validation for demo
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.success(f"Welcome back, {username}!")
                        # Here you would typically validate credentials against a database
                    else:
                        st.session_state.login_attempts += 1
                        if st.session_state.login_attempts > 3:
                            st.error("Too many failed attempts. Please try again later.")
                        else:
                            st.error("Invalid username or password")
            
            if forgot_password:
                st.session_state.active_tab = 'forgot_password'
                st.session_state.reset_stage = 'request'
                st.rerun()
    
    elif st.session_state.active_tab == 'forgot_password':
        # Password Reset Flow
        if st.session_state.reset_stage == 'request':
            # Step 1: Request password reset
            with st.form("Forgot Password Form"):
                st.subheader("Reset Your Password")
                email = st.text_input("Registered Email Address", placeholder="Enter your email")
                
                col1, col2 = st.columns([1, 1])
                with col1:
                    back_button = st.form_submit_button("Back to Login", use_container_width=True)
                with col2:
                    reset_button = st.form_submit_button("Send Reset Code", use_container_width=True)
                
                if back_button:
                    st.session_state.active_tab = 'login'
                    st.rerun()
                
                if reset_button:
                    if email and validate_email(email):
                        with st.spinner("Sending password reset code..."):
                            success, _ = send_reset_email(email)
                            if success:
                                st.session_state.reset_email = email
                                st.session_state.reset_stage = 'verify'
                                st.success(f"Password reset code sent to {email}")
                                st.rerun()
                            else:
                                st.error("Failed to send reset code. Please try again.")
                    else:
                        st.error("Please enter a valid email address")
        
        elif st.session_state.reset_stage == 'verify':
            # Step 2: Verify reset code
            st.subheader("Verify Reset Code")
            masked_email = mask_email(st.session_state.reset_email)
            
            st.markdown(
                f"""
                <div class="otp-container">
                    <p>A password reset code has been sent to <strong>{masked_email}</strong>. Please check your inbox and enter the code below.</p>
                    <p style="font-size: 12px; color: #666; margin-top: 10px;">If you don't see the email, check your spam folder.</p>
                </div>
                """, 
                unsafe_allow_html=True
            )
            
            with st.form("Reset Code Verification Form"):
                reset_code = st.text_input("Enter reset code", max_chars=6, placeholder="123456")
                
                col1, col2 = st.columns([1, 1])
                with col1:
                    back_button = st.form_submit_button("Back", use_container_width=True)
                with col2:
                    verify_button = st.form_submit_button("Verify Code", use_container_width=True)
                
                if back_button:
                    st.session_state.reset_stage = 'request'
                    st.rerun()
                
                if verify_button:
                    if not reset_code:
                        st.error("Please enter the reset code")
                    else:
                        # Verify the reset code
                        if verify_reset_code(reset_code):
                            st.session_state.reset_stage = 'reset'
                            st.rerun()
                        else:
                            st.error("Invalid or expired reset code")
            
            # Add resend option
            if st.button("Resend Reset Code"):
                with st.spinner("Resending password reset code..."):
                    success, _ = send_reset_email(st.session_state.reset_email)
                    if success:
                        masked_email = mask_email(st.session_state.reset_email)
                        st.success(f"New reset code sent to {masked_email}")
                    else:
                        st.error("Failed to resend reset code. Please try again.")
        
        elif st.session_state.reset_stage == 'reset':
            # Step 3: Create new password
            st.subheader("Create New Password")
            
            with st.form("New Password Form"):
                new_password = st.text_input("New Password", type="password", placeholder="Enter new password")
                
                # Show password strength
                if new_password:
                    show_password_strength(new_password)
                
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter new password")
                
                submit_button = st.form_submit_button("Reset Password", use_container_width=True)
                
                if submit_button:
                    if not new_password or not confirm_password:
                        st.error("Please fill in all fields")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match")
                    else:
                        # Additional password validation
                        is_valid, pw_message = validate_password(new_password)
                        if not is_valid:
                            st.error(f"Password too weak: {pw_message}")
                        else:
                            # Here you would update the password in your database
                            # For this demo, we'll just show a success message
                            st.markdown(
                                """
                                <div class="success-container">
                                    <div class="success-icon">✓</div>
                                    <div class="success-title">Password Reset Successful!</div>
                                    <div class="success-message">Your password has been updated successfully.</div>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                            
                            # Add button to return to login
                            if st.button("Return to Login", use_container_width=True, type="primary"):
                                st.session_state.active_tab = 'login'
                                st.rerun()
    
    else:
        # Signup Process - multi-stage
        if st.session_state.signup_stage == 'info':
            # Signup Form - First stage (user information)
            with st.form("Signup Form"):
                st.subheader("Create New Account")
                
                # Personal Information
                st.markdown('<p class="section-header">Personal Information</p>', unsafe_allow_html=True)
                col1, col2 = st.columns(2)
                with col1:
                    first_name = st.text_input("First Name*", placeholder="Enter your first name")
                with col2:
                    last_name = st.text_input("Last Name*", placeholder="Enter your last name")
                
                email = st.text_input("Email Address*", placeholder="Enter your email")
                phone = st.text_input("Phone Number*", placeholder="Enter your 10-digit phone number")
                
                # Validate email and phone in real-time
                if email and not validate_email(email):
                    st.markdown('<p class="help-text" style="color:red;">Please enter a valid email address</p>', unsafe_allow_html=True)
                if phone and not validate_phone(phone):
                    st.markdown('<p class="help-text" style="color:red;">Please enter a valid 10-digit phone number</p>', unsafe_allow_html=True)
                
                # Location Information
                st.markdown('<p class="section-header">Location Information</p>', unsafe_allow_html=True)
                col1, col2 = st.columns(2)
                with col1:
                    state = st.selectbox("State*", ["Andhra Pradesh", "Telangana", "Karnataka", "Tamil Nadu", 
                                                  "Maharashtra", "Uttar Pradesh", "Punjab", "Other"])
                    village = st.text_input("Village/Mandal*", placeholder="Enter your village or mandal name")
                with col2:
                    district = st.selectbox("District*", ["Select District", "Guntur", "Krishna", "Prakasam", "Nellore", 
                                                        "Hyderabad", "Rangareddy", "Medchal", "Warangal", "Other"])
                    pin_code = st.text_input("PIN Code*", placeholder="Enter your 6-digit postal code")
                
                # Validate PIN code
                if pin_code and (not pin_code.isdigit() or len(pin_code) != 6):
                    st.markdown('<p class="help-text" style="color:red;">Please enter a valid 6-digit PIN code</p>', unsafe_allow_html=True)
                
                # Account Credentials
                st.markdown('<p class="section-header">Account Credentials</p>', unsafe_allow_html=True)
                new_username = st.text_input("Choose a Username*", placeholder="Enter username")
                new_password = st.text_input("Create Password*", type="password", placeholder="Enter password")
                
                # Show password strength
                if new_password:
                    show_password_strength(new_password)
                
                confirm_password = st.text_input("Confirm Password*", type="password", placeholder="Re-enter password")
                
                # Terms and conditions
                agree = st.checkbox("I agree to the terms and conditions*")
                
                col1, col2, col3 = st.columns([1, 2, 1])
                with col2:
                    signup_submit = st.form_submit_button("Proceed to Verification", use_container_width=True)
                
                if signup_submit:
                    # Validate all fields
                    required_fields = {
                        "First Name": first_name,
                        "Last Name": last_name,
                        "Email": email,
                        "Phone": phone,
                        "State": state,
                        "District": district if district != "Select District" else "",  # Ensure "Select District" is treated as empty
                        "Village": village,
                        "PIN Code": pin_code,
                        "Username": new_username,
                        "Password": new_password,
                        "Confirm Password": confirm_password
                    }
                    
                    missing_fields = [field for field, value in required_fields.items() if not value]
                    
                    if missing_fields:
                        st.error(f"Please fill in all required fields: {', '.join(missing_fields)}")
                    elif not validate_email(email):
                        st.error("Please enter a valid email address")
                    elif not validate_phone(phone):
                        st.error("Please enter a valid 10-digit phone number")
                    elif not pin_code.isdigit() or len(pin_code) != 6:
                        st.error("Please enter a valid 6-digit PIN code")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match!")
                    elif not agree:
                        st.error("Please agree to the terms and conditions")
                    else:
                        # Additional password validation
                        is_valid, pw_message = validate_password(new_password)
                        if not is_valid:
                            st.error(f"Password too weak: {pw_message}")
                        else:
                            # Store user data in session state
                            st.session_state.user_data = {
                                "personal_info": {
                                    "first_name": first_name,
                                    "last_name": last_name,
                                    "email": email,
                                    "phone": phone
                                },
                                "location_info": {
                                    "state": state,
                                    "district": district,
                                    "village": village,
                                    "pin_code": pin_code
                                },
                                "account_info": {
                                    "username": new_username,
                                    "password": new_password  # Note: In real app, store hashed password
                                }
                            }
                            
                            # Send OTP to user's email
                            with st.spinner("Sending verification code to your email..."):
                                if send_otp_email(email):
                                    st.success(f"Verification code sent to {email}")
                                    st.session_state.signup_stage = 'otp'
                                    st.rerun()
                                else:
                                    st.error("Failed to send verification code. Please try again.")
        
        elif st.session_state.signup_stage == 'otp':
            # OTP Verification Stage
            st.subheader("Email Verification")
            # Use the mask_email function to mask the email
            masked_email = mask_email(st.session_state.user_data['personal_info']['email'])
            st.markdown(
                f"""
                <div class="otp-container">
                    <p>A verification code has been sent to <strong>{masked_email}</strong>. Please check your inbox and enter the 6-digit code below.</p>
                    <p style="font-size: 12px; color: #666; margin-top: 10px;">If you don't see the email, check your spam folder.</p>
                </div>
                """, 
                unsafe_allow_html=True
            )
            
            with st.form("OTP Verification Form"):
                otp_code = st.text_input("Enter 6-digit verification code", max_chars=6, placeholder="123456")
                
                col1, col2 = st.columns([1, 1])
                with col1:
                    back_button = st.form_submit_button("Back", use_container_width=True)
                with col2:
                    verify_button = st.form_submit_button("Verify Email", use_container_width=True)
                
                if back_button:
                    st.session_state.signup_stage = 'info'
                    st.rerun()
                
                if verify_button:
                    if not otp_code or len(otp_code) != 6:
                        st.error("Please enter a valid 6-digit code")
                    else:
                        # Verify OTP
                        if verify_otp(otp_code):
                            # Display success message
                            st.markdown(
                                """
                                <div class="success-container">
                                    <div class="success-icon">✓</div>
                                    <div class="success-title">Account Successfully Created and Verified!</div>
                                    <div class="success-message">Good to go! Your account has been created and verified successfully.</div>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                            st.balloons()
                            
                            # Here you would save the user data to a database
                            # Set the success flag for the login page
                            st.session_state.verification_success = True
                            st.session_state.show_proceed_button = True
                            
                            # Reset OTP attempts
                            st.session_state.otp_attempts = 0
                        else:
                            st.error("Invalid or expired verification code. Please try again.")
            
            # Move the Proceed to Login button outside the form
            if 'show_proceed_button' in st.session_state and st.session_state.show_proceed_button:
                if st.button("Proceed to Login", use_container_width=True, type="primary"):
                    st.session_state.signup_stage = 'info'
                    st.session_state.active_tab = 'login'
                    st.session_state.show_proceed_button = False
                    st.rerun()
                
                # Add countdown for auto-redirect
                countdown_placeholder = st.empty()
                for i in range(5, 0, -1):
                    countdown_placeholder.markdown(
                        f"""
                        <div style="text-align: center; margin-top: 20px; font-size: 14px; color: #666;">
                            Redirecting to login page in {i} seconds...
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    time.sleep(1)
                
                # Redirect to login page
                st.session_state.signup_stage = 'info'
                st.session_state.active_tab = 'login'
                st.session_state.show_proceed_button = False
                st.rerun()
            
            # Add resend OTP option
            if st.button("Resend Verification Code"):
                with st.spinner("Resending verification code..."):
                    if send_otp_email(st.session_state.user_data['personal_info']['email']):
                        # Use the masked email when showing the success message
                        masked_email = mask_email(st.session_state.user_data['personal_info']['email'])
                        st.success(f"New verification code sent to {masked_email}")
                    else:
                        st.error("Failed to resend verification code. Please try again.")