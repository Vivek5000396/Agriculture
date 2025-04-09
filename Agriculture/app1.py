import streamlit as st
import base64

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
        </style>
        """,
        unsafe_allow_html=True
    )

# Set background
add_bg_from_local("C:/Users/rishi/Desktop/Agriculture/agriculture (2).jpg")

# Create sidebar navigation
with st.sidebar:
    st.title("Navigation")
    selected_page = st.radio("Go to", ["Project Landing Page", "Login/Signup"])

# Display title - Guaranteed to stay in one line
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
else:
    # Initialize session state for tab selection
    if 'active_tab' not in st.session_state:
        st.session_state.active_tab = 'login'
    
    # Horizontal buttons for Login/Signup
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Login", key="login_btn", use_container_width=True, 
                   type="primary" if st.session_state.active_tab == 'login' else "secondary"):
            st.session_state.active_tab = 'login'
    with col2:
        if st.button("Sign Up", key="signup_btn", use_container_width=True,
                   type="primary" if st.session_state.active_tab == 'signup' else "secondary"):
            st.session_state.active_tab = 'signup'
    
    # Display the appropriate form based on the active tab
    if st.session_state.active_tab == 'login':
        # Login Form
        with st.form("Login Form"):
            st.subheader("Login to Your Account")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            remember_me = st.checkbox("Remember me")
            login_submit = st.form_submit_button("Login")
            
            if login_submit:
                if username and password:
                    st.success(f"Welcome back, {username}!")
                    # Here you would typically validate credentials against a database
                else:
                    st.error("Please enter both username and password")
    
    else:
        # Signup Form
        with st.form("Signup Form"):
            st.subheader("Create New Account")
            
            # Personal Information
            st.markdown('<p class="section-header">Personal Information</p>', unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                first_name = st.text_input("First Name", placeholder="Enter your first name")
            with col2:
                last_name = st.text_input("Last Name", placeholder="Enter your last name")
            
            email = st.text_input("Email Address", placeholder="Enter your email")
            phone = st.text_input("Phone Number", placeholder="Enter your phone number")
            
            # Location Information
            st.markdown('<p class="section-header">Location Information</p>', unsafe_allow_html=True)
            col1, col2 = st.columns(2)
            with col1:
                state = st.selectbox("State", ["Andhra Pradesh", "Telangana", "Karnataka", "Tamil Nadu", 
                                             "Maharashtra", "Uttar Pradesh", "Punjab", "Other"])
                village = st.text_input("Village/Mandal", placeholder="Enter your village or mandal name")
            with col2:
                district = st.selectbox("District", ["Select District", "Guntur", "Krishna", "Prakasam", "Nellore", 
                                                  "Hyderabad", "Rangareddy", "Medchal", "Warangal", "Other"])
                pin_code = st.text_input("PIN Code", placeholder="Enter your postal code")
            
            # Account Credentials
            st.markdown('<p class="section-header">### Account Credentials</p>', unsafe_allow_html=True)
            new_username = st.text_input("Choose a Username", placeholder="Enter username")
            col1, col2 = st.columns(2)
            with col1:
                new_password = st.text_input("Create Password", type="password", placeholder="Enter password")
            with col2:
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
            
            # Terms and conditions
            agree = st.checkbox("I agree to the terms and conditions")
            
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                signup_submit = st.form_submit_button("Create Account", use_container_width=True)
            
            if signup_submit:
                if not all([first_name, last_name, email, new_username, new_password, confirm_password]):
                    st.error("Please fill in all required fields")
                elif new_password != confirm_password:
                    st.error("Passwords do not match!")
                elif not agree:
                    st.error("Please agree to the terms and conditions")
                else:
                    # Here you would typically save the user data to a database
                    user_data = {
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
                    st.success(f"Account created successfully for {first_name} {last_name}!")
                    st.balloons()
                    st.session_state.active_tab = 'login'  # Switch to login tab after successful signup