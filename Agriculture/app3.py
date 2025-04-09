import streamlit as st
import base64
import google.generativeai as genai
from datetime import datetime, timedelta
from pymongo import MongoClient
from pymongo.server_api import ServerApi
import bcrypt
import pyotp
import smtplib
from email.message import EmailMessage
import time
import re
import string
import random

# Configure Gemini API with the new model
genai.configure(api_key="AIzaSyDOrv3RayLX8j0B9C_cWwncoDjVfVHwZds")

# MongoDB Connection Setup
MONGO_URI = "mongodb+srv://rishiande9999:Buji9899@cluster0.tgv6k.mongodb.net/test?retryWrites=true&w=majority"

def get_mongo_client():
    try:
        client = MongoClient(
            MONGO_URI,
            server_api=ServerApi('1'),
            tls=True,
            tlsAllowInvalidCertificates=False
        )
        client.admin.command('ping')
        return client
    except Exception as e:
        st.error(f"Failed to connect to MongoDB: {str(e)}")
        return None

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

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
            color: #333333; /* Dark text for light mode */
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
            color: #1A3C34; /* Dark green for title */
            text-shadow: 1px 1px 3px rgba(0, 0, 0, 0.1);
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
            background-color: #E8F5E9; /* Light green button */
            color: #2E7D32; /* Dark green text */
            border-radius: 5px;
            border: 1px solid #C8E6C9;
            cursor: pointer;
        }}
        
        /* Sidebar styling */
        .sidebar .sidebar-content {{
            background-color: #F5F5F5; /* Light gray sidebar */
            color: #333333;
        }}
        
        /* Content box styling */
        .content-box {{
            background-color: rgba(255, 255, 255, 0.95); /* Slightly transparent white */
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            color: #333333;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
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
            background-color: #FFFFFF;
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #E0E0E0;
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
            background-color: #E8F5E9;
            color: #2E7D32;
            border: 1px solid #C8E6C9;
        }}
        
        .horizontal-buttons button.active {{
            background-color: #4CAF50;
            color: white;
            border: none;
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
            color: #666666;
            margin-top: -15px;
            margin-bottom: 15px;
        }}
        
        /* Crop image styling */
        .crop-image {{
            max-width: 100%;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }}

        /* OTP container styling */
        .otp-container {{
            margin-top: 20px;
            padding: 15px;
            background-color: #F9F9F9;
            border-radius: 8px;
            border-left: 4px solid #4CAF50;
            color: #333333;
        }}

        /* Success message styling */
        .success-container {{
            background-color: #E8F5E9;
            border-left: 5px solid #4CAF50;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            text-align: center;
            color: #2E7D32;
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
            color: #333333;
        }}
        
        /* Error message styling */
        .error-container {{
            background-color: #FFEBEE;
            border-left: 5px solid #F44336;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            color: #D32F2F;
        }}
        
        /* Password strength meter */
        .password-strength {{
            height: 5px;
            margin-top: 5px;
            margin-bottom: 15px;
            background-color: #E0E0E0;
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

# Validation Functions from First Code
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_phone(phone):
    return phone.isdigit() and len(phone) == 10

def validate_password(password):
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
    if not email or '@' not in email:
        return email
    parts = email.split('@')
    username = parts[0]
    domain = parts[1]
    if len(username) > 1:
        masked_username = username[0] + '*' * (len(username) - 1)
    else:
        masked_username = username
    return f"{masked_username}@{domain}"

# Email Sending Functions from First Code
def send_email(receiver_email, subject, content_type="verification", code=None):
    if code is None:
        if content_type == "verification":
            secret_key = pyotp.random_base32()
            totp = pyotp.TOTP(secret_key, interval=180)
            code = totp.now()
            st.session_state.otp_secret = secret_key
            st.session_state.otp_time = time.time()
            st.session_state.otp_attempts = 0
        else:
            characters = string.ascii_letters + string.digits
            code = ''.join(random.choice(characters) for _ in range(6))
            st.session_state.reset_code = code
            st.session_state.reset_code_time = time.time()
            st.session_state.reset_attempts = 0
    
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 465
    SENDER_NAME = "AgricultureChatbot"
    SENDER_EMAIL = "rishiande99999@gmail.com"
    SENDER_PASSWORD = "vnhhrieggmpngufz"
    
    msg = EmailMessage()
    msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg["X-Priority"] = "1"
    msg["X-Mailer"] = "AgricultureChatbot"
    msg["Importance"] = "High"
    
    if content_type == "verification":
        plain_text = f"""Agriculture Planning System Verification
Your one-time verification code is: {code}
This code will expire in 3 minutes.
If you didn't request this code, please ignore this email.
Thank you,
Agriculture Planning System Team
"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px;">
                <div style="text-align: center;">
                    <h1 style="color: #2E7D32;">🌾 Smart Agriculture</h1>
                    <p style="color: #666;">Account Verification</p>
                </div>
                <div style="background-color: #E8F5E9; padding: 25px; border-radius: 8px; text-align: center;">
                    <p>Your verification code is:</p>
                    <div style="font-size: 32px; color: #4CAF50; font-weight: bold; letter-spacing: 5px;">{code}</div>
                    <p>(Expires in 3 minutes)</p>
                </div>
            </div>
        </body>
        </html>
        """
    else:
        plain_text = f"""Agriculture Planning System Password Reset
Your password reset code is: {code}
This code will expire in 3 minutes.
If you didn't request this code, please ignore this email.
Thank you,
Agriculture Planning System Team
"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px;">
                <div style="text-align: center;">
                    <h1 style="color: #2E7D32;">🌾 Smart Agriculture</h1>
                    <p style="color: #666;">Password Reset Request</p>
                </div>
                <div style="background-color: #E8F5E9; padding: 25px; border-radius: 8px; text-align: center;">
                    <p>Your password reset code is:</p>
                    <div style="font-size: 32px; color: #4CAF50; font-weight: bold; letter-spacing: 5px;">{code}</div>
                    <p>(Expires in 3 minutes)</p>
                </div>
            </div>
        </body>
        </html>
        """
    
    msg.set_content(plain_text)
    msg.add_alternative(html_content, subtype='html')
    
    try:
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        return True, code
    except Exception as e:
        st.error(f"Error sending email: {str(e)}")
        return False, None

def send_otp_email(receiver_email):
    success, _ = send_email(receiver_email, "Your Agriculture Verification Code", content_type="verification")
    return success

def send_reset_email(receiver_email):
    success, code = send_email(receiver_email, "Your Agriculture Password Reset Code", content_type="reset")
    return success, code

# Verification Functions from First Code
def verify_otp(entered_otp):
    if 'otp_secret' not in st.session_state or 'otp_time' not in st.session_state:
        return False
    st.session_state.otp_attempts += 1
    if st.session_state.otp_attempts > 3:
        st.error("Too many attempts. Please request a new OTP.")
        return False
    current_time = time.time()
    if current_time - st.session_state.otp_time > 180:
        st.error("OTP has expired. Please request a new one.")
        return False
    totp = pyotp.TOTP(st.session_state.otp_secret, interval=180)
    return totp.verify(entered_otp)

def verify_reset_code(entered_code):
    if 'reset_code' not in st.session_state or 'reset_code_time' not in st.session_state:
        return False
    st.session_state.reset_attempts += 1
    if st.session_state.reset_attempts > 3:
        st.error("Too many attempts. Please request a new reset code.")
        return False
    current_time = time.time()
    if current_time - st.session_state.reset_code_time > 180:
        st.error("Reset code has expired. Please request a new one.")
        return False
    return st.session_state.reset_code == entered_code

def show_password_strength(password):
    strength = 0
    feedback = ""
    if len(password) >= 8:
        strength += 1
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
    colors = ["#FF0000", "#FF4500", "#FFA500", "#9ACD32", "#008000"]
    color_index = min(strength, len(colors) - 1)
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

# Initialize session state for background image
if 'bg_image' not in st.session_state:
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/agriculture (2).jpg"

# Create sidebar navigation
with st.sidebar:
    st.title("Navigation")
    selected_page = st.radio("Go to", ["Project Landing Page", "Login/Signup", "Dashboard", "Crop Management", 
                                       "Land & Resource Calculator", "Irrigation Schedule", "Yield Prediction", 
                                       "Weather Live Updates", "Market Price Predictions", "AI-Based Pest Control", 
                                       "Soil Health Analysis", "Fertilizer Recommendations", "Crop Rotation Planning", 
                                       "Farm Management Insights"])

# Change background image based on selected page
if selected_page == "Crop Management":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Crop Management.jpg"
elif selected_page == "Land & Resource Calculator":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Land (2).jpg"
elif selected_page == "Irrigation Schedule":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Irrigation.jpg"
elif selected_page == "Yield Prediction":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Yield.jpg"
elif selected_page == "Weather Live Updates":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Weather.jpg"
elif selected_page == "Market Price Predictions":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Market.jpeg"
elif selected_page == "AI-Based Pest Control":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/pest.jpeg"
elif selected_page == "Soil Health Analysis":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Soil Health.jpg"
elif selected_page == "Fertilizer Recommendations":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Fertilizer.jpg"
elif selected_page == "Crop Rotation Planning":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Crop rotation.jpg"
elif selected_page == "Farm Management Insights":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Automation.png"
else:
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/agriculture (2).jpg"

# Set background
add_bg_from_local(st.session_state.bg_image)

# Display title
st.markdown('<div class="title-container">Smart Agriculture Planning System</div>', unsafe_allow_html=True)

# Display content based on sidebar selection
if selected_page == "Project Landing Page":
    st.markdown(
        """
        <div class="content-box">
            <h2>About the Project</h2>
            <p>The Smart Agriculture Assistant is an AI-powered web application designed to assist farmers and agricultural professionals in optimizing crop management, irrigation scheduling, yield prediction, and weather monitoring. The platform integrates Google Gemini AI for intelligent recommendations and the OpenWeather API for real-time weather updates. By leveraging AI and data-driven insights, this system helps farmers improve productivity, conserve resources, and make informed decisions about their crops and land.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

elif selected_page == "Login/Signup":
    # Initialize session states from First Code
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
            st.session_state.verification_success = False
        
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
                    client = get_mongo_client()
                    if client:
                        db = client["agriculture_db"]
                        users = db["users"]
                        user = users.find_one({"account_info.username": username})
                        if user and check_password(password, user["account_info"]["password"]):
                            st.success(f"Welcome back, {username}!")
                            st.session_state.user = user
                            st.session_state.login_attempts = 0
                            st.balloons()
                        else:
                            st.session_state.login_attempts += 1
                            if st.session_state.login_attempts > 3:
                                st.error("Too many failed attempts. Please try again later or reset your password.")
                            else:
                                st.error("Invalid username or password")
            
            if forgot_password:
                st.session_state.active_tab = 'forgot_password'
                st.session_state.reset_stage = 'request'
                st.rerun()

    elif st.session_state.active_tab == 'forgot_password':
        if st.session_state.reset_stage == 'request':
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
                        if verify_reset_code(reset_code):
                            st.session_state.reset_stage = 'reset'
                            st.rerun()
                        else:
                            st.error("Invalid or expired reset code")
            
            if st.button("Resend Reset Code"):
                with st.spinner("Resending password reset code..."):
                    success, _ = send_reset_email(st.session_state.reset_email)
                    if success:
                        masked_email = mask_email(st.session_state.reset_email)
                        st.success(f"New reset code sent to {masked_email}")
                    else:
                        st.error("Failed to resend reset code. Please try again.")
        
        elif st.session_state.reset_stage == 'reset':
            st.subheader("Create New Password")
            with st.form("New Password Form"):
                new_password = st.text_input("New Password", type="password", placeholder="Enter new password")
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
                        is_valid, pw_message = validate_password(new_password)
                        if not is_valid:
                            st.error(f"Password too weak: {pw_message}")
                        else:
                            client = get_mongo_client()
                            if client:
                                db = client["agriculture_db"]
                                users = db["users"]
                                users.update_one(
                                    {"personal_info.email": st.session_state.reset_email},
                                    {"$set": {"account_info.password": hash_password(new_password)}}
                                )
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
                                if st.button("Return to Login", use_container_width=True, type="primary"):
                                    st.session_state.active_tab = 'login'
                                    st.rerun()

    else:  # Signup
        if st.session_state.signup_stage == 'info':
            with st.form("Signup Form"):
                st.subheader("Create New Account")
                
                st.markdown('<p class="section-header">Personal Information</p>', unsafe_allow_html=True)
                col1, col2 = st.columns(2)
                with col1:
                    first_name = st.text_input("First Name*", placeholder="Enter your first name")
                with col2:
                    last_name = st.text_input("Last Name*", placeholder="Enter your last name")
                
                email = st.text_input("Email Address*", placeholder="Enter your email")
                phone = st.text_input("Phone Number*", placeholder="Enter your 10-digit phone number")
                
                if email and not validate_email(email):
                    st.markdown('<p class="help-text" style="color:red;">Please enter a valid email address</p>', unsafe_allow_html=True)
                if phone and not validate_phone(phone):
                    st.markdown('<p class="help-text" style="color:red;">Please enter a valid 10-digit phone number</p>', unsafe_allow_html=True)
                
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
                
                if pin_code and (not pin_code.isdigit() or len(pin_code) != 6):
                    st.markdown('<p class="help-text" style="color:red;">Please enter a valid 6-digit PIN code</p>', unsafe_allow_html=True)
                
                st.markdown('<p class="section-header">Account Credentials</p>', unsafe_allow_html=True)
                new_username = st.text_input("Choose a Username*", placeholder="Enter username")
                new_password = st.text_input("Create Password*", type="password", placeholder="Enter password")
                if new_password:
                    show_password_strength(new_password)
                confirm_password = st.text_input("Confirm Password*", type="password", placeholder="Re-enter password")
                
                agree = st.checkbox("I agree to the terms and conditions*")
                
                col1, col2, col3 = st.columns([1, 2, 1])
                with col2:
                    signup_submit = st.form_submit_button("Proceed to Verification", use_container_width=True)
                
                if signup_submit:
                    required_fields = {
                        "First Name": first_name,
                        "Last Name": last_name,
                        "Email": email,
                        "Phone": phone,
                        "State": state,
                        "District": district if district != "Select District" else "",
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
                        is_valid, pw_message = validate_password(new_password)
                        if not is_valid:
                            st.error(f"Password too weak: {pw_message}")
                        else:
                            client = get_mongo_client()
                            if client:
                                db = client["agriculture_db"]
                                users = db["users"]
                                if users.find_one({"$or": [{"account_info.username": new_username}, {"personal_info.email": email}]}):
                                    st.error("Username or email already exists")
                                else:
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
                                            "password": hash_password(new_password)
                                        },
                                        "created_at": datetime.now(),
                                        "last_login": None,
                                        "account_status": "pending"  # Pending verification
                                    }
                                    with st.spinner("Sending verification code to your email..."):
                                        if send_otp_email(email):
                                            st.success(f"Verification code sent to {email}")
                                            st.session_state.signup_stage = 'otp'
                                            st.rerun()
                                        else:
                                            st.error("Failed to send verification code. Please try again.")
        
        elif st.session_state.signup_stage == 'otp':
            st.subheader("Email Verification")
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
                        if verify_otp(otp_code):
                            client = get_mongo_client()
                            if client:
                                db = client["agriculture_db"]
                                users = db["users"]
                                st.session_state.user_data["account_status"] = "active"
                                users.insert_one(st.session_state.user_data)
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
                                st.session_state.verification_success = True
                                st.session_state.show_proceed_button = True
                                st.session_state.otp_attempts = 0
                        else:
                            st.error("Invalid or expired verification code. Please try again.")
            
            if 'show_proceed_button' in st.session_state and st.session_state.show_proceed_button:
                if st.button("Proceed to Login", use_container_width=True, type="primary"):
                    st.session_state.signup_stage = 'info'
                    st.session_state.active_tab = 'login'
                    st.session_state.show_proceed_button = False
                    st.rerun()
            
            if st.button("Resend Verification Code"):
                with st.spinner("Resending verification code..."):
                    if send_otp_email(st.session_state.user_data['personal_info']['email']):
                        masked_email = mask_email(st.session_state.user_data['personal_info']['email'])
                        st.success(f"New verification code sent to {masked_email}")
                    else:
                        st.error("Failed to resend verification code. Please try again.")

elif selected_page == "Dashboard":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Dashboard.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>🌱 Smart Agriculture Dashboard</h2>
            <p>Central hub for all farming insights and tools</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Key Metrics Overview
    st.markdown('<p class="section-header">📊 Farm Snapshot</p>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Crops Tracked", "5", "2 new")
    col2.metric("Soil Health", "Good", "↑8%")
    col3.metric("Water Saved", "12,000L", "This month")
    col4.metric("Yield Forecast", "+15%", "Next season")

    # Feature Cards Grid
    st.markdown('<p class="section-header">🛠️ Tools & Features</p>', unsafe_allow_html=True)
    
    # Row 1
    col1, col2, col3 = st.columns(3)
    with col1:
        with st.container(border=True):
            st.markdown("🌾 **Crop Management**")
            st.write("Get AI advice for any crop")
            if st.button("Access", key="crop_mgmt", use_container_width=True):
                st.session_state.selected_page = "Crop Management"
                st.rerun()
    
    with col2:
        with st.container(border=True):
            st.markdown("🧮 **Land Calculator**")
            st.write("Measure land & water needs")
            if st.button("Access", key="land_calc", use_container_width=True):
                st.session_state.selected_page = "Land & Resource Calculator"
                st.rerun()

    with col3:
        with st.container(border=True):
            st.markdown("💧 **Irrigation Planner**")
            st.write("Schedule watering automatically")
            if st.button("Access", key="irrigation", use_container_width=True):
                st.session_state.selected_page = "Irrigation Schedule"
                st.rerun()

    # Row 2
    col1, col2, col3 = st.columns(3)
    with col1:
        with st.container(border=True):
            st.markdown("📈 **Market Prices**")
            st.write("Predict crop selling prices")
            if st.button("Access", key="market", use_container_width=True):
                st.session_state.selected_page = "Market Price Predictions"
                st.rerun()

    with col2:
        with st.container(border=True):
            st.markdown("🦗 **Pest Control**")
            st.write("Identify & treat crop threats")
            if st.button("Access", key="pest", use_container_width=True):
                st.session_state.selected_page = "AI-Based Pest Control"
                st.rerun()

    with col3:
        with st.container(border=True):
            st.markdown("🌿 **Soil Health**")
            st.write("Test and improve your soil")
            if st.button("Access", key="soil", use_container_width=True):
                st.session_state.selected_page = "Soil Health Analysis"
                st.rerun()

    # Row 3
    col1, col2, col3 = st.columns(3)
    with col1:
        with st.container(border=True):
            st.markdown("🧪 **Fertilizer Guide**")
            st.write("Custom NPK recommendations")
            if st.button("Access", key="fertilizer", use_container_width=True):
                st.session_state.selected_page = "Fertilizer Recommendations"
                st.rerun()

    with col2:
        with st.container(border=True):
            st.markdown("🔄 **Crop Rotation**")
            st.write("Plan soil-friendly cycles")
            if st.button("Access", key="rotation", use_container_width=True):
                st.session_state.selected_page = "Crop Rotation Planning"
                st.rerun()

    with col3:
        with st.container(border=True):
            st.markdown("☁️ **Weather**")
            st.write("Real-time farm weather")
            if st.button("Access", key="weather", use_container_width=True):
                st.session_state.selected_page = "Weather Updates"
                st.rerun()

    # AI Insights Section
    st.markdown('<p class="section-header">🤖 AI Recommendations</p>', unsafe_allow_html=True)
    with st.container(border=True):
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = """Give 3 actionable farming recommendations for this week based on:
            - Current season (monsoon)
            - Common crops in India (rice, wheat, vegetables)
            - Soil conservation priorities
            
            Format as bullet points with emojis"""
            response = model.generate_content(prompt)
            st.markdown(response.text)
        except:
            st.warning("AI service temporarily unavailable")

    # Recent Activity Timeline
    st.markdown('<p class="section-header">⏳ Recent Activity</p>', unsafe_allow_html=True)
    with st.container(border=True):
        st.write("""
        - 🟢 **Today**: Completed wheat irrigation (Field A)
        - 🟡 **Yesterday**: Soil test submitted (pH 6.2)
        - 🔴 **2 days ago**: Pest alert - aphids detected in tomato field
        """)

    # Quick Actions Footer
    st.markdown("---")
    st.markdown("**🚀 Quick Actions**")
    st.button("Generate Weekly Report", use_container_width=True)
    st.button("Alert Farm Assistant", use_container_width=True)

elif selected_page == "Crop Management":
    with st.form("crop_form"):
        st.subheader("🌾 Crop Management Assistant")
        
        crop_name = st.text_input("Enter the crop name you're interested in", 
                                 placeholder="e.g., Rice, Wheat, Cotton...")
        
        user_question = st.text_area("Ask your crop-related question", 
                                    placeholder="e.g., What are the ideal growing conditions for this crop?")
        
        submit_button = st.form_submit_button("Get AI Response")
        
        if submit_button:
            if not crop_name:
                st.warning("Please enter a crop name")
            elif not user_question:
                st.warning("Please ask a question about the crop")
            else:
                with st.spinner("Getting AI response..."):
                    try:
                        model = genai.GenerativeModel('gemini-1.5-flash')
                        prompt = f"""You are an agricultural expert assistant. Provide detailed, practical advice about {crop_name}.
                        Question: {user_question}
                        Please provide:
                        1. A concise answer to the specific question
                        2. Additional relevant information about {crop_name} that might be helpful
                        3. Any important warnings or considerations
                        4. Best practices for cultivation
                        Format your response with clear headings and bullet points where appropriate."""
                        response = model.generate_content(prompt)
                        st.markdown(
                            f"""
                            <div class="content-box">
                                <h3>AI Response for {crop_name}</h3>
                                <p>{response.text}</p>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                    except Exception as e:
                        st.error(f"An error occurred: {str(e)}")
                        st.info("Please try again later or check your internet connection.")

elif selected_page == "Land & Resource Calculator":
    st.markdown(
        """
        <div class="content-box">
            <h2>Land & Resource Calculator</h2>
            <p>This tool helps farmers calculate land area and estimate water requirements for different crops.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    tab1, tab2 = st.tabs(["Land Area Calculator", "Water Requirement Estimator"])
    
    with tab1:
        with st.form("land_area_form"):
            st.subheader("Land Area Calculator")
            col1, col2 = st.columns(2)
            with col1:
                length = st.number_input("Length (in meters)", min_value=0.0, value=0.0, step=0.1)
            with col2:
                width = st.number_input("Width (in meters)", min_value=0.0, value=0.0, step=0.1)
            
            calculate_area = st.form_submit_button("Calculate Area")
            
            if calculate_area:
                if length > 0 and width > 0:
                    area = length * width
                    area_acres = area * 0.000247105
                    st.success(f"Total Land Area: {area:.2f} square meters ({area_acres:.2f} acres)")
                else:
                    st.warning("Please enter valid length and width values")
    
    with tab2:
        with st.form("water_requirement_form"):
            st.subheader("Water Requirement Estimator")
            crop_type = st.selectbox("Select Crop Type", 
                                  ["Rice", "Wheat", "Corn", "Cotton", "Sugarcane", "Vegetables", "Other"])
            land_size = st.number_input("Land Size (in acres)", min_value=0.0, value=1.0, step=0.1)
            water_requirements = {
                "Rice": 5000000,
                "Wheat": 2000000,
                "Corn": 2500000,
                "Cotton": 3500000,
                "Sugarcane": 6000000,
                "Vegetables": 3000000,
                "Other": 2500000
            }
            estimate_water = st.form_submit_button("Estimate Water Requirement")
            if estimate_water:
                if land_size > 0:
                    water_needed = water_requirements[crop_type] * land_size
                    st.success(f"Estimated water requirement for {crop_type}: {water_needed:,.0f} liters")
                    st.info(f"Note: This is an approximate value. Actual requirements may vary based on soil type, climate, and irrigation method.")
                else:
                    st.warning("Please enter a valid land size")

elif selected_page == "Irrigation Schedule":
    st.markdown(
        """
        <div class="content-box">
            <h2>🌊 Irrigation Schedule Planner</h2>
            <p>Plan your crop irrigation schedule based on crop type and frequency requirements.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.form("irrigation_form"):
        st.subheader("Create Irrigation Schedule")
        crop_type = st.selectbox("Select Crop Type", ["Rice", "Wheat", "Corn", "Cotton", "Sugarcane", "Vegetables", "Fruits", "Other"])
        frequency = st.selectbox("Irrigation Frequency", [1, 2, 3, 4, 5, 7, 10, 14], format_func=lambda x: f"Every {x} day{'s' if x > 1 else ''}")
        start_date = st.date_input("Start Date", datetime.now())
        cycles = st.slider("Number of Irrigation Cycles", min_value=1, max_value=20, value=10)
        submit_schedule = st.form_submit_button("Generate Schedule")
        
        if submit_schedule:
            if not crop_type:
                st.warning("Please select a crop type")
            else:
                schedule = []
                current_date = start_date
                for i in range(cycles):
                    schedule.append({
                        "Cycle": i+1,
                        "Date": current_date.strftime("%Y-%m-%d"),
                        "Day": current_date.strftime("%A"),
                        "Crop": crop_type,
                        "Notes": f"Irrigation day for {crop_type}"
                    })
                    current_date += timedelta(days=frequency)
                st.success(f"Irrigation Schedule for {crop_type} (Every {frequency} days)")
                st.dataframe(schedule)
                csv = "\n".join([f"{item['Cycle']},{item['Date']},{item['Day']},{item['Crop']},{item['Notes']}" for item in schedule])
                st.download_button("Download Schedule", data=f"Cycle,Date,Day,Crop,Notes\n{csv}", file_name=f"{crop_type}_irrigation_schedule.csv", mime="text/csv")
                st.markdown(
                    """
                    <div class="content-box">
                        <h4>💡 Irrigation Tips for {}</h4>
                        <ul>
                            <li>Early morning is the best time for irrigation to reduce evaporation loss</li>
                            <li>Monitor soil moisture regularly to adjust schedule as needed</li>
                            <li>Consider drip irrigation for water-intensive crops like {} to conserve water</li>
                        </ul>
                    </div>
                    """.format(crop_type, crop_type if crop_type in ["Rice", "Sugarcane"] else "your crop"),
                    unsafe_allow_html=True
                )

elif selected_page == "Yield Prediction":
    st.markdown(
        """
        <div class="content-box">
            <h2>🌾 Crop Yield Prediction</h2>
            <p>Estimate potential crop yield based on crop type and land area.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.form("yield_form"):
        st.subheader("Yield Estimation Parameters")
        crop_type = st.selectbox("Select Crop Type", ["Rice", "Wheat", "Corn", "Cotton", "Sugarcane", "Vegetables", "Fruits", "Other"])
        land_size = st.number_input("Land Size (in acres)", min_value=0.1, value=1.0, step=0.1)
        soil_quality = st.select_slider("Soil Quality", options=["Poor", "Average", "Good", "Excellent"], value="Average")
        irrigation_type = st.radio("Irrigation Method", ["Rain-fed", "Flood", "Drip", "Sprinkler"])
        submit_yield = st.form_submit_button("Estimate Yield")
        
        if submit_yield:
            if not crop_type or land_size <= 0:
                st.warning("Please select a crop type and enter valid land size")
            else:
                yield_data = {
                    "Rice": {"Poor": 1500, "Average": 2500, "Good": 3500, "Excellent": 4500},
                    "Wheat": {"Poor": 1000, "Average": 2000, "Good": 3000, "Excellent": 4000},
                    "Corn": {"Poor": 1200, "Average": 2200, "Good": 3200, "Excellent": 4200},
                    "Cotton": {"Poor": 800, "Average": 1500, "Good": 2200, "Excellent": 3000},
                    "Sugarcane": {"Poor": 30000, "Average": 50000, "Good": 70000, "Excellent": 90000},
                    "Vegetables": {"Poor": 2000, "Average": 4000, "Good": 6000, "Excellent": 8000},
                    "Fruits": {"Poor": 1500, "Average": 3000, "Good": 5000, "Excellent": 7000},
                    "Other": {"Poor": 1000, "Average": 2000, "Good": 3000, "Excellent": 4000}
                }
                irrigation_multipliers = {"Rain-fed": 0.8, "Flood": 1.0, "Drip": 1.2, "Sprinkler": 1.1}
                base_yield = yield_data[crop_type][soil_quality]
                adjusted_yield = base_yield * irrigation_multipliers[irrigation_type]
                total_yield = adjusted_yield * land_size
                st.success(f"Estimated Yield for {crop_type}: {total_yield:,.0f} kg")
                st.markdown(
                    """
                    <div class="content-box">
                        <h4>💡 Yield Improvement Tips</h4>
                        <ul>
                            <li>Regular soil testing can help optimize fertilizer use</li>
                            <li>Consider crop rotation to maintain soil health</li>
                            <li>Proper pest management can significantly improve yields</li>
                            <li>Using high-quality seeds can increase yield by 15-20%</li>
                        </ul>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

elif selected_page == "Weather Live Updates":
    st.markdown(
        """
        <div class="content-box">
            <h2>☁️ Weather Updates</h2>
            <p>Get real-time weather information and AI-powered agricultural recommendations based on weather patterns.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.form("weather_form"):
        st.subheader("Get Weather Information")
        col1, col2 = st.columns(2)
        with col1:
            city = st.text_input("City Name", placeholder="e.g., Hyderabad, Mumbai, Delhi...")
        with col2:
            state = st.text_input("State (Optional)", placeholder="e.g., Telangana, Maharashtra...")
        get_weather = st.form_submit_button("Get Weather Update")
        
        if get_weather:
            if not city:
                st.warning("Please enter at least a city name")
            else:
                with st.spinner("Fetching weather data..."):
                    try:
                        import requests
                        location_query = f"{city},{state}" if state else city
                        api_key = "1b257a2339d842b8bfb182459252403"
                        url = f"http://api.weatherapi.com/v1/current.json?key={api_key}&q={location_query}&aqi=no"
                        response = requests.get(url).json()
                        if 'error' in response:
                            st.error(f"Error fetching weather data: {response['error']['message']}")
                        else:
                            current = response['current']
                            location = response['location']
                            location_display = f"{location['name']}"
                            if 'region' in location and location['region']:
                                location_display += f", {location['region']}"
                            location_display += f", {location['country']}"
                            st.markdown(
                                f"""
                                <div class="content-box">
                                    <h3>Current Weather in {location_display}</h3>
                                    <p><img src="https:{current['condition']['icon']}" width=50> <strong>{current['condition']['text']}</strong></p>
                                    <p><strong>Temperature:</strong> {current['temp_c']}°C (Feels like {current['feelslike_c']}°C)</p>
                                    <p><strong>Humidity:</strong> {current['humidity']}%</p>
                                    <p><strong>Precipitation:</strong> {current['precip_mm']} mm</p>
                                    <p><strong>Pressure:</strong> {current['pressure_mb']} hPa</p>
                                    <p><strong>Wind:</strong> {current['wind_kph']} km/h {current['wind_dir']}</p>
                                    <p><strong>UV Index:</strong> {current['uv']}</p>
                                    <p><strong>Last Updated:</strong> {current['last_updated']}</p>
                                </div>
                                """,
                                unsafe_allow_html=True
                            )
                            with st.spinner("Generating farming recommendations..."):
                                model = genai.GenerativeModel('gemini-1.5-flash')
                                prompt = f"""Provide agricultural recommendations for farmers in {location_display} based on:
                                - Current weather: {current['condition']['text']}
                                - Temperature: {current['temp_c']}°C (Feels like {current['feelslike_c']}°C)
                                - Humidity: {current['humidity']}%
                                - Precipitation: {current['precip_mm']} mm
                                - Wind: {current['wind_kph']} km/h {current['wind_dir']}
                                - UV Index: {current['uv']}
                                Provide 5 specific recommendations focusing on:
                                1. Immediate actions needed (if any)
                                2. Irrigation adjustments
                                3. Crop protection measures
                                4. Ideal farming activities for these conditions
                                5. 3-day outlook preparation"""
                                ai_response = model.generate_content(prompt)
                                st.markdown(
                                    f"""
                                    <div class="content-box">
                                        <h4>🌱 AI Farming Recommendations for {location['name']}</h4>
                                        <p>{ai_response.text}</p>
                                    </div>
                                    """,
                                    unsafe_allow_html=True
                                )
                    except Exception as e:
                        st.error(f"An error occurred: {str(e)}")
                        st.info("Please try again later or check your internet connection.")

elif selected_page == "Market Price Predictions":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Market.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>📈 Market Price Predictions</h2>
            <p>Get AI-powered market price trends and forecasts to help you decide the optimal time to sell your crops.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.form("price_prediction_form"):
        st.subheader("Crop Price Analysis")
        col1, col2 = st.columns(2)
        with col1:
            state = st.selectbox("Select State", ["Andhra Pradesh", "Telangana", "Karnataka", "Tamil Nadu", 
                                                  "Maharashtra", "Uttar Pradesh", "Punjab", "Other"])
        with col2:
            crop_type = st.selectbox("Select Crop Type", ["Rice", "Wheat", "Corn", "Cotton", "Sugarcane", 
                                                          "Tomato", "Potato", "Onion", "Soybean", "Other"])
        analysis_period = st.selectbox("Analysis Period", ["Last 30 days", "Last 3 months", "Last 6 months", "Last 1 year"])
        get_prediction = st.form_submit_button("Get Price Analysis")
        
        if get_prediction:
            with st.spinner("Analyzing market trends..."):
                try:
                    price_trends = {
                        "Rice": [1850, 1900, 1950, 2000, 2050, 2100],
                        "Wheat": [2200, 2150, 2100, 2150, 2200, 2250],
                        "Cotton": [6000, 6100, 6200, 6300, 6400, 6500],
                        "Sugarcane": [3200, 3250, 3300, 3350, 3400, 3450],
                        "Tomato": [1200, 1500, 1800, 2000, 2200, 2400]
                    }
                    trends = price_trends.get(crop_type, [2000, 2100, 2200, 2300, 2400, 2500])
                    st.markdown(
                        f"""
                        <div class="content-box">
                            <h4>💰 {crop_type} Price Trends in {state}</h4>
                            <p>Last 6 months average market prices (per quintal)</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.line_chart(data=trends, use_container_width=True, height=300)
                    with st.spinner("Generating AI predictions..."):
                        model = genai.GenerativeModel('gemini-1.5-flash')
                        prompt = f"""Act as an agricultural market expert. Provide:
                        1. Current {crop_type} price analysis for {state}
                        2. 3-month price forecast based on seasonality and demand
                        3. Best time to sell {crop_type} in the next 6 months
                        4. 3 actionable recommendations for farmers
                        Format with clear headings and bullet points. Use Indian Rupees (₹) for prices."""
                        ai_response = model.generate_content(prompt)
                        st.markdown(
                            f"""
                            <div class="content-box">
                                <h4>📊 AI Market Analysis for {crop_type}</h4>
                                <p>{ai_response.text}</p>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                        st.info("Note: Predictions are based on AI analysis and historical trends. Actual market prices may vary due to unforeseen factors.")
                except Exception as e:
                    st.error(f"Error generating predictions: {str(e)}")
                    st.info("Please try again later or check your internet connection.")

elif selected_page == "AI-Based Pest Control":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/PestControl.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>🦗 AI-Based Pest Control</h2>
            <p>Identify pests and diseases affecting your crops and get AI-powered treatment recommendations.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.form("pest_control_form"):
        st.subheader("Crop Health Analysis")
        col1, col2 = st.columns(2)
        with col1:
            crop_type = st.selectbox("Select Crop Type", ["Rice", "Wheat", "Cotton", "Sugarcane", "Tomato", 
                                                          "Potato", "Corn", "Soybean", "Other Vegetables", "Fruits"])
        with col2:
            growth_stage = st.selectbox("Growth Stage", ["Seedling", "Vegetative", "Flowering", "Fruiting", "Maturity"])
        symptoms = st.text_area("Describe Symptoms or Upload Images*", placeholder="e.g., Yellow spots on leaves, stunted growth, holes in leaves...")
        weather_conditions = st.selectbox("Recent Weather Conditions", ["Dry", "Humid", "Rainy", "Alternating Wet/Dry", "Extreme Heat"])
        analyze_pest = st.form_submit_button("Analyze & Get Recommendations")
        
        if analyze_pest:
            with st.spinner("Analyzing crop health..."):
                try:
                    model = genai.GenerativeModel('gemini-1.5-flash')
                    pest_prompt = f"""Act as an agricultural pest expert. For {crop_type} in {growth_stage} stage showing:
                    Symptoms: {symptoms}
                    Weather: {weather_conditions}
                    Provide:
                    1. Top 3 likely pests/diseases (with scientific names)
                    2. Severity assessment (Low/Medium/High)
                    3. Visual description of each pest/disease
                    4. Conditions favoring their growth"""
                    pest_response = model.generate_content(pest_prompt)
                    treatment_prompt = f"""For the identified pests/diseases in {crop_type}, provide:
                    1. Organic control methods (3-5 options)
                    2. Chemical treatments (with safety precautions)
                    3. Preventive measures
                    4. Recommended treatment schedule
                    5. Weather-specific considerations for {weather_conditions}"""
                    treatment_response = model.generate_content(treatment_prompt)
                    st.markdown(
                        f"""
                        <div class="content-box">
                            <h4>🐛 Pest/Disease Identification for {crop_type}</h4>
                            <p>{pest_response.text}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown(
                        f"""
                        <div class="content-box">
                            <h4>💊 Treatment & Prevention Plan</h4>
                            <p>{treatment_response.text}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown(
                        """
                        <div class="content-box">
                            <h4>🔍 Further Resources</h4>
                            <ul>
                                <li>Contact local agricultural extension officer</li>
                                <li>Submit samples to nearest plant clinic</li>
                                <li>Monitor field daily for symptom progression</li>
                            </ul>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                except Exception as e:
                    st.error(f"Error in pest analysis: {str(e)}")
                    st.info("Please try again later or check your internet connection.")

    with st.expander("📸 Upload Plant Images for AI Analysis (Beta)"):
        uploaded_files = st.file_uploader("Upload clear images of affected plants", type=["jpg", "png", "jpeg"], accept_multiple_files=True)
        if uploaded_files:
            st.warning("Image analysis feature is under development. Currently using text analysis only.")

elif selected_page == "Soil Health Analysis":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Soil Health.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>🌿 Soil Health Analysis</h2>
            <p>Analyze your soil test results and get AI-powered recommendations to improve soil fertility and crop yield.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    with st.form("soil_analysis_form"):
        st.subheader("Soil Test Input")
        col1, col2 = st.columns(2)
        with col1:
            soil_type = st.selectbox("Soil Type", ["Clay", "Sandy", "Loamy", "Silty", "Peaty", "Chalky", "Black Cotton"])
        with col2:
            crop_planned = st.text_input("Planted/Planned Crop", placeholder="e.g., Wheat, Cotton, Tomato...")
        st.markdown('<p class="section-header">Soil Test Parameters</p>', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        with col1:
            ph_level = st.slider("pH Level", min_value=3.0, max_value=10.0, value=7.0, step=0.1)
        with col2:
            organic_carbon = st.slider("Organic Carbon (%)", min_value=0.1, max_value=5.0, value=0.8, step=0.1)
        with col3:
            nitrogen = st.slider("Nitrogen (kg/ha)", min_value=50, max_value=500, value=250, step=10)
        col1, col2, col3 = st.columns(3)
        with col1:
            phosphorus = st.slider("Phosphorus (kg/ha)", min_value=5, max_value=100, value=25, step=1)
        with col2:
            potassium = st.slider("Potassium (kg/ha)", min_value=50, max_value=500, value=150, step=10)
        with col3:
            micronutrients = st.selectbox("Micronutrient Status", ["Deficient", "Marginal", "Adequate", "Sufficient"])
        observations = st.text_area("Additional Observations", placeholder="e.g., Hard crust formation, poor drainage, visible salt deposits...")
        analyze_soil = st.form_submit_button("Analyze Soil Health")
        
        if analyze_soil:
            with st.spinner("Analyzing soil health..."):
                try:
                    model = genai.GenerativeModel('gemini-1.5-flash')
                    prompt = f"""Act as an agricultural soil scientist. Analyze this soil data:
                    - Soil Type: {soil_type}
                    - Planned Crop: {crop_planned}
                    - pH: {ph_level}
                    - Organic Carbon: {organic_carbon}%
                    - Nitrogen: {nitrogen} kg/ha
                    - Phosphorus: {phosphorus} kg/ha
                    - Potassium: {potassium} kg/ha
                    - Micronutrients: {micronutrients}
                    - Observations: {observations}
                    Provide detailed analysis with:
                    1. Soil health assessment (Good/Fair/Poor)
                    2. Major limitations for {crop_planned}
                    3. Nutrient deficiency/excess analysis
                    4. pH adjustment recommendations
                    5. Organic matter improvement plan
                    6. Fertilizer recommendations (NPK ratio)
                    7. Micronutrient management
                    8. Soil structure improvement tips
                    Format with clear headings and bullet points."""
                    response = model.generate_content(prompt)
                    st.markdown(
                        f"""
                        <div class="content-box">
                            <h3>🌱 Soil Health Report for {crop_planned}</h3>
                            <p>{response.text}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown(
                        """
                        <div class="content-box">
                            <h4>📊 Quick Soil Health Indicators</h4>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("pH Status", f"{ph_level}", help=f"Ideal range for {crop_planned}: 6.0-7.5" if crop_planned else "Ideal range: 6.0-7.5")
                    with col2:
                        st.metric("Organic Carbon", f"{organic_carbon}%", "Aim for >1%" if organic_carbon < 1 else "Good level")
                    with col3:
                        st.metric("NPK Balance", f"N:{nitrogen} P:{phosphorus} K:{potassium}", "Check recommendations")
                except Exception as e:
                    st.error(f"Error in soil analysis: {str(e)}")
                    st.info("Please try again later or check your internet connection.")

    with st.expander("📚 Soil Parameter Reference Guide"):
        st.markdown(
            """
            <div class="content-box">
                <h4>Understanding Soil Test Values</h4>
                <ul>
                    <li><strong>pH Level:</strong> Most crops prefer 6.0-7.5. Below 6.0 is acidic, above 7.5 is alkaline</li>
                    <li><strong>Organic Carbon:</strong> Ideal >1%. Below 0.5% is poor, above 1.5% is excellent</li>
                    <li><strong>Nitrogen (N):</strong> 250-500 kg/ha good for most crops</li>
                    <li><strong>Phosphorus (P):</strong> 20-50 kg/ha adequate for most crops</li>
                    <li><strong>Potassium (K):</strong> 150-300 kg/ha good for most crops</li>
                </ul>
                <p>Note: Optimal values vary by crop type and soil conditions.</p>
            </div>
            """,
            unsafe_allow_html=True
        )

elif selected_page == "Fertilizer Recommendations":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/Fertilizer.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>🧪 AI-Based Fertilizer Recommendations</h2>
            <p>Get customized fertilizer suggestions based on your crop needs and soil conditions to optimize plant growth.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    with st.form("fertilizer_form"):
        st.subheader("Crop and Soil Information")
        col1, col2 = st.columns(2)
        with col1:
            crop_type = st.selectbox("Select Crop Type", ["Rice", "Wheat", "Cotton", "Sugarcane", "Maize", 
                                                          "Tomato", "Potato", "Vegetables", "Fruits", "Pulses"])
        with col2:
            growth_stage = st.selectbox("Current Growth Stage", ["Pre-planting", "Seedling", "Vegetative", 
                                                                 "Flowering", "Fruiting", "Maturity"])
        st.markdown('<p class="section-header">Soil Test Results</p>', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        with col1:
            nitrogen = st.select_slider("Nitrogen Level", options=["Very Low", "Low", "Medium", "High", "Very High"])
        with col2:
            phosphorus = st.select_slider("Phosphorus Level", options=["Very Low", "Low", "Medium", "High", "Very High"])
        with col3:
            potassium = st.select_slider("Potassium Level", options=["Very Low", "Low", "Medium", "High", "Very High"])
        col1, col2 = st.columns(2)
        with col1:
            ph_level = st.slider("Soil pH", min_value=4.0, max_value=9.0, value=6.5, step=0.1)
        with col2:
            organic_matter = st.select_slider("Organic Matter", options=["Very Poor", "Poor", "Average", "Good", "Excellent"])
        irrigation_type = st.selectbox("Irrigation Method", ["Flood", "Drip", "Sprinkler", "Rainfed", "Other"])
        get_recommendations = st.form_submit_button("Get Fertilizer Recommendations")
        
        if get_recommendations:
            with st.spinner("Generating customized recommendations..."):
                try:
                    model = genai.GenerativeModel('gemini-1.5-flash')
                    prompt = f"""Act as an agricultural fertilizer expert. Provide recommendations for:
                    Crop: {crop_type} ({growth_stage} stage)
                    Soil Conditions:
                    - N: {nitrogen}
                    - P: {phosphorus}
                    - K: {potassium}
                    - pH: {ph_level}
                    - Organic Matter: {organic_matter}
                    - Irrigation: {irrigation_type}
                    Provide:
                    1. Overall nutrient requirement assessment
                    2. Recommended NPK ratio for this stage
                    3. Top 3 chemical fertilizer options with application rates
                    4. Top 3 organic alternatives with application methods
                    5. Micronutrient suggestions (if needed)
                    6. pH adjustment recommendations (if needed)
                    7. Application schedule for current growth stage
                    8. # Special considerations for {irrigation_type} irrigation
                    Format with clear headings and bullet points. Include quantities in kg/ha."""
                    response = model.generate_content(prompt)
                    st.markdown(
                        f"""
                        <div class="content-box">
                            <h3>🧑‍🌾 Fertilizer Plan for {crop_type}</h3>
                            <p>{response.text}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown(
                        """
                        <div class="content-box">
                            <h4>📊 Fertilizer Calculator</h4>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    col1, col2 = st.columns(2)
                    with col1:
                        area = st.number_input("Field Area (acres)", min_value=0.1, max_value=1000.0, value=1.0, step=0.1)
                    with col2:
                        selected_fertilizer = st.selectbox("Select Fertilizer to Calculate", ["Urea", "DAP", "MOP", "NPK Complex", "Organic Manure"])
                    if area > 0:
                        recommendation = f"For {area} acres, you'll need approximately:\n"
                        recommendation += f"- {area*50} kg of {selected_fertilizer} for basal application\n"
                        recommendation += f"- {area*25} kg for top dressing during growth"
                        fertilizer_rates = {
                            "Urea": 100,  # kg/ha Nitrogen source
                            "DAP": 50,    # kg/ha Phosphorus source
                            "MOP": 60,    # kg/ha Potassium source
                            "NPK Complex": 120,  # kg/ha balanced
                            "Organic Manure": 5000  # kg/ha organic matter
                        }
                        total_amount = (fertilizer_rates[selected_fertilizer] * area) / 2.471  # Convert ha to acres
                        st.success(f"For {area} acres, you’ll need approximately {total_amount:.1f} kg of {selected_fertilizer}")
                except Exception as e:
                    st.error(f"Error generating recommendations: {str(e)}")
                    st.info("Please try again later or check your internet connection.")

    with st.expander("📚 Fertilizer Application Tips"):
        st.markdown(
            """
            <div class="content-box">
                <h4>Best Practices for Fertilizer Use</h4>
                <ul>
                    <li><strong>Timing:</strong> Apply during early morning or late afternoon</li>
                    <li><strong>Mixing:</strong> Don’t mix fertilizers unless specified compatible</li>
                    <li><strong>Organic:</strong> Compost manure for 2-3 months before application</li>
                    <li><strong>Irrigation:</strong> Water lightly after application to help absorption</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True
        )

elif selected_page == "Crop Rotation Planning":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/CropRotation.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>🔄 AI-Powered Crop Rotation Planning</h2>
            <p>Generate optimal crop rotation cycles to maintain soil health and maximize yields.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    with st.form("rotation_form"):
        st.subheader("Field Information")
        col1, col2 = st.columns(2)
        with col1:
            current_crop = st.selectbox("Current/Most Recent Crop", ["Rice", "Wheat", "Cotton", "Sugarcane", "Maize", 
                                                                    "Pulses", "Oilseeds", "Vegetables", "Fallow", "Other"])
        with col2:
            seasons_grown = st.number_input("Seasons Grown Continuously", min_value=1, max_value=10, value=1)
        st.markdown('<p class="section-header">Soil Health Indicators</p>', unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        with col1:
            pest_problems = st.multiselect("Recent Pest/Disease Issues", ["Nematodes", "Fungal Diseases", "Bacterial Wilt", 
                                                                         "Root Rot", "Aphids", "None"])
        with col2:
            soil_quality = st.select_slider("Current Soil Quality", options=["Very Poor", "Poor", "Average", "Good", "Excellent"])
        with col3:
            organic_matter = st.select_slider("Organic Matter Content", options=["Very Low (<0.5%)", "Low (0.5-1%)", 
                                                                               "Medium (1-2%)", "High (2-3%)", "Very High (>3%)"])
        st.markdown('<p class="section-header">Farm Characteristics</p>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            irrigation_type = st.selectbox("Irrigation Method", ["Rainfed", "Flood", "Drip", "Sprinkler", "Mixed"])
        with col2:
            farm_size = st.selectbox("Farm Size Category", ["Small (<2 ha)", "Medium (2-5 ha)", "Large (>5 ha)"])
        rotation_preference = st.radio("Rotation Priority", ["Soil Health Improvement", "Disease Break", "Income Stability", "Labor Reduction"])
        generate_plan = st.form_submit_button("Generate Rotation Plan")
        if generate_plan:
            with st.spinner("Creating optimized rotation plan..."):
                try:
                    model = genai.GenerativeModel('gemini-1.5-flash')
                    prompt = f"""Create a 3-year crop rotation plan for:
                    - Current Crop: {current_crop} (grown {seasons_grown} seasons)
                    - Soil Quality: {soil_quality}
                    - Organic Matter: {organic_matter}
                    - Pest Issues: {pest_problems if pest_problems else 'None'}
                    - Irrigation: {irrigation_type}
                    - Farm Size: {farm_size}
                    - Priority: {rotation_preference}
                    Provide:
                    1. Recommended 3-year rotation sequence with benefits
                    2. Expected soil health improvements
                    3. Pest/disease risk reduction strategy
                    4. Cover crop suggestions (if applicable)
                    5. Expected yield impacts
                    6. Special considerations for {irrigation_type} systems
                    7. Month-by-month implementation calendar
                    Format with clear headings and bullet points."""
                    response = model.generate_content(prompt)
                    st.markdown(
                        f"""
                        <div class="content-box">
                            <h3>🌾 Recommended Crop Rotation Plan</h3>
                            <p>{response.text}</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    st.markdown(
                        """
                        <div class="content-box">
                            <h4>📅 Sample Rotation Calendar</h4>
                            <p>Below is a suggested planting schedule based on your inputs:</p>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                    calendar_data = {
                        "Year 1": ["Legumes", "Wheat", "Cover Crop"],
                        "Year 2": ["Vegetables", "Millets", "Green Manure"],
                        "Year 3": ["Oilseeds", "Pulses", "Cover Crop"]
                    }
                    st.dataframe(calendar_data)
                    with st.expander("💵 Economic Impact Analysis"):
                        st.markdown(
                            f"""
                            <div class="content-box">
                                <h5>Projected Benefits</h5>
                                <ul>
                                    <li>Estimated 15-25% yield improvement by Year 3</li>
                                    <li>30-50% reduction in pesticide costs</li>
                                    <li>Improved soil value over time</li>
                                    <li>More stable income through diversified crops</li>
                                </ul>
                                <p>Note: Actual results may vary based on implementation and weather conditions.</p>
                            </div>
                            """,
                            unsafe_allow_html=True
                        )
                except Exception as e:
                    st.error(f"Error generating rotation plan: {str(e)}")
                    st.info("Please try again later or check your internet connection.")

    with st.expander("📚 Crop Rotation Fundamentals"):
        st.markdown(
            """
            <div class="content-box">
                <h4>Basic Principles of Crop Rotation</h4>
                <ol>
                    <li><strong>Alternate Crop Families:</strong> Don’t follow crops from same family</li>
                    <li><strong>Nitrogen Management:</strong> Follow heavy feeders with nitrogen fixers</li>
                    <li><strong>Root Depth Variation:</strong> Alternate deep and shallow rooted crops</li>
                    <li><strong>Pest Cycle Breaking:</strong> Disrupt pest/disease host cycles</li>
                    <li><strong>Soil Structure:</strong> Include crops with different residue types</li>
                    <li><strong>Economic Balance:</strong> Mix cash crops with soil builders</li>
                </ol>
                <p>Good rotation typically includes grains, legumes, and cover crops.</p>
            </div>
            """,
            unsafe_allow_html=True
        )

elif selected_page == "Farm Management Insights":
    st.session_state.bg_image = "C:/Users/rishi/Desktop/Agriculture/FarmManagement.jpg"
    st.markdown(
        """
        <div class="content-box">
            <h2>🚜 Automated Farm Management Insights</h2>
            <p>AI-powered daily recommendations and alerts for optimal farm operations.</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
    if 'farm_profile' not in st.session_state:
        st.session_state.farm_profile = None
    
    with st.expander("🏡 Setup Your Farm Profile", expanded=not st.session_state.farm_profile):
        with st.form("farm_profile_form"):
            st.subheader("Farm Configuration")
            col1, col2 = st.columns(2)
            with col1:
                farm_name = st.text_input("Farm Name", placeholder="My Farm")
                total_area = st.number_input("Total Area (acres)", min_value=0.1, value=5.0, step=0.1)
                main_crop = st.selectbox("Primary Crop", ["Rice", "Wheat", "Cotton", "Vegetables", "Fruits", "Other"])
            with col2:
                farm_location = st.text_input("Nearest Village/Town", placeholder="Enter location")
                irrigation_type = st.selectbox("Irrigation System", ["Rainfed", "Drip", "Sprinkler", "Flood", "Mixed"])
                soil_type = st.selectbox("Dominant Soil Type", ["Clay", "Sandy", "Loamy", "Black Cotton", "Other"])
            st.markdown("**Field Sections** (Add up to 5 fields)")
            fields = []
            for i in range(1, 6):
                col1, col2, col3 = st.columns(3)
                with col1:
                    field_name = st.text_input(f"Field {i} Name", placeholder=f"Field-{i}", key=f"field_{i}_name")
                with col2:
                    field_area = st.number_input("Area (acres)", min_value=0.1, value=1.0, step=0.1, key=f"field_{i}_area")
                with col3:
                    field_crop = st.selectbox("Current Crop", ["None"]+["Rice", "Wheat", "Cotton", "Vegetables", "Fruits", "Other"], key=f"field_{i}_crop")
                if field_name:
                    fields.append((field_name, field_area, field_crop))
            save_profile = st.form_submit_button("Save Farm Profile")
            if save_profile:
                st.session_state.farm_profile = {
                    "farm_name": farm_name or "My Farm",
                    "location": farm_location,
                    "total_area": total_area,
                    "main_crop": main_crop,
                    "irrigation": irrigation_type,
                    "soil_type": soil_type,
                    "fields": fields
                }
                st.success("Farm profile saved successfully!")
    
    if st.session_state.farm_profile:
        st.markdown(
            f"""
            <div class="content-box">
                <h3>👨‍🌾 {st.session_state.farm_profile['farm_name']} Dashboard</h3>
                <p>📍 {st.session_state.farm_profile.get('location', 'Location not specified')} | 
                🌱 {st.session_state.farm_profile['main_crop']} | 
                💧 {st.session_state.farm_profile['irrigation']} Irrigation</p>
            </div>
            """,
            unsafe_allow_html=True
        )
        with st.spinner("Generating daily insights..."):
            try:
                model = genai.GenerativeModel('gemini-1.5-flash')
                prompt = f"""Generate farm management insights for:
                Farm: {st.session_state.farm_profile['farm_name']}
                Location: {st.session_state.farm_profile.get('location', 'Unknown')}
                Main Crop: {st.session_state.farm_profile['main_crop']}
                Soil: {st.session_state.farm_profile['soil_type']}
                Irrigation: {st.session_state.farm_profile['irrigation']}
                Fields: {st.session_state.farm_profile['fields']}
                Current Date: {datetime.now().strftime('%Y-%m-%d')}
                Provide:
                1. TODAY'S PRIORITY TASKS (3-5 most important tasks)
                2. WEATHER ALERTS (if any)
                3. PEST/DISEASE WATCH (based on crop stage)
                4. IRRIGATION RECOMMENDATIONS
                5. SOIL HEALTH TIPS
                6. EQUIPMENT MAINTENANCE REMINDERS
                7. MARKET OPPORTUNITIES
                Format with clear headings, emojis, and bullet points. Be concise but specific."""
                response = model.generate_content(prompt)
                st.markdown(
                    f"""
                    <div class="content-box">
                        <h4>📅 Daily Recommendations for {datetime.now().strftime('%B %d, %Y')}</h4>
                        <p>{response.text}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
                st.markdown('<p class="section-header">Field-Specific Recommendations</p>', unsafe_allow_html=True)
                for field in st.session_state.farm_profile['fields']:
                    field_name, area, crop = field
                    if crop != "None":
                        with st.expander(f"🌾 {field_name} ({area} acres - {crop})"):
                            try:
                                field_prompt = f"""Generate field-specific recommendations for:
                                Field: {field_name}
                                Crop: {crop}
                                Area: {area} acres
                                Soil: {st.session_state.farm_profile['soil_type']}
                                Irrigation: {st.session_state.farm_profile['irrigation']}
                                Provide:
                                1. Current growth stage assessment
                                2. Immediate action items
                                3. Nutrient requirements
                                4. Pest monitoring focus areas
                                5. Water needs
                                Be field-specific and practical."""
                                field_response = model.generate_content(field_prompt)
                                st.markdown(field_response.text)
                            except Exception as e:
                                st.error(f"Couldn’t generate field insights: {str(e)}")
                st.markdown('<p class="section-header">Farm Health Indicators</p>', unsafe_allow_html=True)
                cols = st.columns(4)
                indicators = [
                    ("🌱 Crop Health", "Good", "green"),
                    ("💧 Water Needs", "Moderate", "blue"),
                    ("⚡ Urgent Tasks", "2", "orange"),
                    ("📈 Yield Forecast", "+12%", "green")
                ]
                for i, (label, value, color) in enumerate(indicators):
                    cols[i].metric(label, value)
            except Exception as e:
                st.error(f"Error generating insights: {str(e)}")
                st.info("Please try again later or check your internet connection.")
    
    else:
        st.warning("Please set up your farm profile to get insights")
    
    if st.session_state.farm_profile:
        with st.expander("📈 Historical Data Analysis"):
            st.markdown(
                """
                <div class="content-box">
                    <h4>Farm Performance Trends</h4>
                    <p>Historical analysis coming soon - this will track:</p>
                    <ul>
                        <li>Yield patterns across seasons</li>
                        <li>Input cost correlations</li>
                        <li>Weather impact analysis</li>
                        <li>Soil health trends</li>
                    </ul>
                </div>
                """,
                unsafe_allow_html=True
            )
            st.line_chart({"Yield (tons)": [3.2, 3.5, 3.1, 3.8, 4.0]})

# End of the main script