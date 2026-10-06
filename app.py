import streamlit as st
from UI.dashboard import implement_chatbot

st.set_page_config(
    page_title="AI Chatbot with Guardrails",
    layout="wide"
)

if __name__ == "__main__":
    st.title("AI Chatbot with Guardrails")
    st.write("Welcome to the AI Chatbot! This application allows you to interact with an AI model and get responses to your queries.")

    st.markdown("<br>", unsafe_allow_html=True)

    implement_chatbot()