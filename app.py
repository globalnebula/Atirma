import streamlit as st
import firebase_admin
from firebase_admin import credentials, auth, firestore
from groq import Groq

cred = credentials.Certificate("atirma-1908.json")

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)

db = firestore.client()

def initialize_groq():
    client = Groq(api_key="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")
    return client

# Google login method
def google_login():
    google_auth_url = (
        "https://accounts.google.com/o/oauth2/v2/auth?"
        "scope=openid%20email%20profile&"
        "response_type=token&"
        "redirect_uri=http://localhost:8501/"
        "client_id=993882413076-gi6vj89l4i1vmc5nk97o2e9hdoo2jn8j.apps.googleusercontent.com"
    )
    st.markdown(f'<a href="{google_auth_url}" target="_self"><button class="google-button">Google</button></a>', unsafe_allow_html=True)

from pymongo import MongoClient
import bcrypt

client = MongoClient("mongodb+srv://kunalachintya:kunal1908@atirma.fqk36.mongodb.net/?retryWrites=true&w=majority&connectTimeoutMS=30000&appName=atirma")

db = client['atirma']
users_collection = db['atirma']

def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_password):
    """Checks the hashed password."""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def email_signup_login():
    option = st.selectbox('Choose an option', ['Sign Up', 'Log In'])
    email = st.text_input("Enter your email")
    password = st.text_input("Enter your password", type="password")

    if option == 'Sign Up':
        if st.button('Register'):
            # Check if user already exists
            if users_collection.find_one({"email": email}):
                st.error("User already exists with this email.")
            else:
                # Hash password and store user in MongoDB with default subscribed as False
                hashed_password = hash_password(password)
                users_collection.insert_one({"email": email, "password": hashed_password, "subscribed": False})
                st.success("User registered successfully! Please complete payment to access the AI service.")
    
    elif option == 'Log In':
        if st.button('Log In'):
            # Retrieve user from MongoDB
            user = users_collection.find_one({"email": email})
            if user:
                if check_password(password, user['password']):
                    st.session_state.authenticated = True
                    st.session_state.user_email = email
                    st.session_state.subscription_active = user.get("subscribed", False)  # Set subscription status
                    st.success("Logged in successfully")
                else:
                    st.error("Incorrect password. Please try again.")
            else:
                st.error("No user found with this email.")

def complete_payment():
    users_collection.update_one({"email": st.session_state.user_email}, {"$set": {"subscribed": True}})
    st.success("Payment successful! You now have access to the AI service.")
    st.success("Click on Verify, again to continue")
    st.session_state.subscription_active = True




def payment_gateway():
    st.write("Atirma Payment Portal")
    
    st.write("Scan the QR code to pay via UPI:")
    st.image("qr.jpg")

    if st.button("Verify Payment"):
        
        st.write("Validating payment...")
        
        
        complete_payment()



def generate_chat_summary(user_message):
    summary = user_message.split('.')[0]
    return summary[:50]

sys_prompt = "Your name is Atirma and you are developed and fine-tuned by Kunal Achintya Reddy a student at Amrita, Kerala. You are an advanced code assistant, an expert in software development, debugging, and architecture design. Your goal is to assist developers by providing:\n\n    Accurate and Efficient Code Solutions:\n        Write clean, optimized, and well-structured code snippets.\n        Ensure solutions adhere to best coding practices for readability, performance, and scalability.\n        Suggest improvements to code by following language-specific conventions and frameworks.\n\n    Professional Guidance:\n        Act as a mentor, providing detailed explanations behind your code suggestions.\n        Be friendly yet professional, offering insightful recommendations on improving code quality.\n        For every solution, offer tips or advice on potential optimizations or pitfalls to watch out for.\n        Provide industry-standard practices (e.g., SOLID principles, DRY, KISS).\n\n    Multilingual Programming Support:\n        Support multiple programming languages such as Python, JavaScript, Java, C++, HTML/CSS, SQL, and more.\n        Respond in a way that matches the language’s style and paradigm (e.g., object-oriented in Java, functional in Python).\n        Explain key language features or concepts when required, such as recursion, lambda functions, closures, or decorators.\n\n    Problem Solving & Debugging:\n        Analyze bugs, explain potential causes, and offer solutions or debugging strategies.\n        Assist with error handling and unit testing, and provide example test cases.\n        Help refactor or modify code to improve performance, modularity, or maintainability.\n\n    Architecture and Design Patterns:\n        Provide guidance on implementing design patterns (Singleton, Observer, Factory, etc.) where appropriate.\n        Offer architectural advice for both small projects and large-scale systems, considering factors like scalability, security, and maintainability.\n        Suggest the right software architecture (MVC, Microservices, Layered) based on the project’s complexity.\n\n    Documentation and Version Control:\n        Provide example comments and docstrings in code for easy comprehension.\n        Suggest useful Git commands for version control, explain branching strategies (e.g., GitFlow), and help resolve merge conflicts.\n        Encourage best practices for project documentation (README files, changelogs).\n\n    Technologies & Tools Expertise:\n        Recommend relevant libraries, frameworks, or tools for the task at hand.\n        Help developers integrate third-party APIs and explain configuration setups (e.g., CI/CD pipelines, Docker, Kubernetes).\n        Stay updated with new technologies and provide insights on when and why to use them.\n\n    Interactive Problem Solving:\n        Engage in step-by-step walkthroughs for complex problems.\n        Ask clarifying questions if the problem is ambiguous or lacks sufficient details.\n        Offer alternative solutions when there are multiple ways to approach a task.\n\n    Security Awareness:\n        Ensure code suggestions follow security best practices (e.g., sanitizing inputs, avoiding SQL injection, encrypting sensitive data).\n        Provide guidance on secure coding practices for different frameworks or languages.\n        Assist with implementing authentication and authorization in systems.\n\n    Learning & Growth:\n        Encourage continuous learning by recommending educational resources, articles, or documentation.\n        Tailor explanations to the user’s expertise level (beginner, intermediate, advanced).\n        Offer guidance on setting up environments (e.g., virtual environments, package management).\n\nWhen responding:\n\n    Maintain a friendly and collaborative tone.\n    Be concise yet thorough in explanations, ensuring the user understands the rationale behind suggestions.\n    Always verify that your code works as expected and addresses the user’s needs.\n\nYour mission is to act as the developer’s go-to coding partner, offering expert-level support while promoting growth and knowledge sharing."
def interact_with_groq(user_message, client, use_history=True):
    global sys_prompt
    try:
        if use_history:
            system_prompt = st.session_state.chat_history + "\n[continue]"
        else:
            system_prompt = sys_prompt
            
        completion = client.chat.completions.create(
            model="llama3-groq-70b-8192-tool-use-preview",
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_message
                }
            ],
            temperature=1,
            max_tokens=1024,
            top_p=1,
            stream=True,
            stop=None,
        )

        llm_response = ""
        for chunk in completion:
            llm_response += chunk.choices[0].delta.content or ""

        if use_history:
            st.session_state.chat_history += "\nUser: " + user_message + "\nAI: " + llm_response
        else:
            st.session_state.chat_history = "User: " + user_message + "\nAI: " + llm_response

        st.session_state.last_message = user_message
        st.write(llm_response)

    except Exception as e:
        st.error(f"An error occurred: {e}")
        print(f"Error: {e}")

def main():
    st.title("$$Atirma AI^{beta}$$")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "user_email" not in st.session_state:
        st.session_state.user_email = ""
    if "subscription_active" not in st.session_state:
        st.session_state.subscription_active = True
    if "user_message" not in st.session_state:
        st.session_state.user_message = ""
    if "chat_summary" not in st.session_state:
        st.session_state.chat_summary = []
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = ""

    if not st.session_state.authenticated:
        auth_method = st.selectbox("Login Method", ["Email & Password"])
        email_signup_login()
    else:
        st.sidebar.write("Logged in as:", st.session_state.user_email)

        client = initialize_groq()

        st.subheader("`Coding != Rocket Science`")
        if st.session_state.subscription_active:
            st.session_state.user_message = st.text_area("Ask something:")

            use_history = st.checkbox("Include previous context", value=True)

            if st.button("Submit"):
                if st.session_state.user_message:
                    chat_summary = generate_chat_summary(st.session_state.user_message)
                    st.session_state.chat_summary.append(chat_summary)

                    interact_with_groq(st.session_state.user_message, client, use_history)
                else:
                    st.warning("Please enter a message to submit.")

            # Button to start a new chat
            if st.sidebar.button("New Chat"):
                st.session_state.chat_history = ""
                st.success("New chat started!")

            # Display chat history in the sidebar
            st.sidebar.subheader("Chat History")
            for idx, summary in enumerate(st.session_state.chat_summary):
                if st.sidebar.button(summary, key=f"chat_summary_{idx}"):
                    st.write(f"Chat {idx + 1}: {summary}")
        else:
            st.warning("Please complete your payment to access the AI service.")
            payment_gateway()

if __name__ == '__main__':
    main()
